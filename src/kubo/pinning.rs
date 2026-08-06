//! Best-effort background cleanup for named local and remote pins.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
};

use tokio::{sync::mpsc, time::Duration};
use tracing::{debug, warn};

const DEFAULT_QUEUE_CAPACITY: usize = 64;
const CLEANUP_YIELD: Duration = Duration::from_millis(100);

/// A fully confirmed pin that must never be removed by a cleanup job.
#[derive(Clone, Debug)]
pub struct PinCleanupRequest {
    pub kubo_url: String,
    pub name: String,
    pub protected_cid: String,
    pub remote_service: Option<String>,
    pub batch_size: usize,
}

#[derive(Clone, Debug, Eq)]
struct PinCleanupKey {
    kubo_url: String,
    name: String,
    remote_service: Option<String>,
}

impl PartialEq for PinCleanupKey {
    fn eq(&self, other: &Self) -> bool {
        self.kubo_url == other.kubo_url
            && self.name == other.name
            && self.remote_service == other.remote_service
    }
}

impl Hash for PinCleanupKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kubo_url.hash(state);
        self.name.hash(state);
        self.remote_service.hash(state);
    }
}

impl From<&PinCleanupRequest> for PinCleanupKey {
    fn from(request: &PinCleanupRequest) -> Self {
        Self {
            kubo_url: request.kubo_url.clone(),
            name: request.name.clone(),
            remote_service: request.remote_service.clone(),
        }
    }
}

/// Detached, bounded cleanup scheduler.
///
/// A full queue deliberately drops new cleanup work. The next publication of
/// the same named pin will schedule another best-effort pass.
#[derive(Clone, Debug)]
pub struct PinCleanupScheduler {
    pending: Arc<Mutex<HashMap<PinCleanupKey, PinCleanupRequest>>>,
    wake: mpsc::Sender<PinCleanupKey>,
}

impl PinCleanupScheduler {
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_QUEUE_CAPACITY)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (wake, receiver) = mpsc::channel(capacity);
        tokio::spawn(run_cleanup_worker(Arc::clone(&pending), receiver));
        Self { pending, wake }
    }

    /// Queue cleanup without awaiting Kubo or queue capacity.
    ///
    /// Returns `false` when the bounded queue is full or its worker has ended.
    pub fn schedule(&self, request: PinCleanupRequest) -> bool {
        let key = PinCleanupKey::from(&request);
        let mut pending = self.pending.lock().expect("pin cleanup scheduler poisoned");
        if pending.contains_key(&key) {
            pending.insert(key, request);
            return true;
        }

        match self.wake.try_send(key.clone()) {
            Ok(()) => {
                pending.insert(key, request);
                true
            }
            Err(error) => {
                debug!(name = %request.name, error = %error, "dropping bounded pin cleanup job");
                false
            }
        }
    }
}

impl Default for PinCleanupScheduler {
    fn default() -> Self {
        Self::new()
    }
}

async fn run_cleanup_worker(
    pending: Arc<Mutex<HashMap<PinCleanupKey, PinCleanupRequest>>>,
    mut receiver: mpsc::Receiver<PinCleanupKey>,
) {
    while let Some(key) = receiver.recv().await {
        let request = pending
            .lock()
            .expect("pin cleanup scheduler poisoned")
            .remove(&key);
        let Some(request) = request else {
            continue;
        };
        cleanup_one_batch(&request).await;
    }
}

async fn cleanup_one_batch(request: &PinCleanupRequest) {
    let batch_size = request.batch_size.max(1);
    cleanup_local_batch(request, batch_size).await;
    if request.remote_service.is_some() {
        cleanup_remote_batch(request, batch_size).await;
    }
    tokio::time::sleep(CLEANUP_YIELD).await;
}

async fn cleanup_local_batch(request: &PinCleanupRequest, batch_size: usize) {
    let pins = match crate::kubo::kubo::list_named_recursive_pins(&request.kubo_url, &request.name)
        .await
    {
        Ok(pins) => pins,
        Err(error) => {
            warn!(name = %request.name, error = %error, "local old-pin lookup failed");
            return;
        }
    };
    for cid in pins
        .into_iter()
        .filter(|cid| cid != &request.protected_cid)
        .take(batch_size)
    {
        if let Err(error) = crate::kubo::kubo::pin_rm(&request.kubo_url, &cid).await {
            warn!(name = %request.name, cid = %cid, error = %error, "local old-pin cleanup failed");
        }
    }
}

async fn cleanup_remote_batch(request: &PinCleanupRequest, batch_size: usize) {
    let Some(service) = request.remote_service.as_deref() else {
        return;
    };
    let pins = match crate::kubo::kubo::list_named_remote_pins(
        &request.kubo_url,
        service,
        &request.name,
    )
    .await
    {
        Ok(pins) => pins,
        Err(error) => {
            warn!(name = %request.name, service, error = %error, "remote old-pin lookup failed");
            return;
        }
    };
    for cid in pins
        .into_iter()
        .filter(|cid| cid != &request.protected_cid)
        .take(batch_size)
    {
        if let Err(error) = crate::kubo::kubo::remote_pin_rm(&request.kubo_url, service, &cid).await
        {
            warn!(name = %request.name, service, cid = %cid, error = %error, "remote old-pin cleanup failed");
        }
    }
}
