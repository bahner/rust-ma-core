//! Best-effort background cleanup for named local and remote pins.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex, OnceLock},
};

use tokio::{sync::mpsc, time::Duration};
use tracing::{debug, warn};

const DEFAULT_QUEUE_CAPACITY: usize = 64;
const CLEANUP_YIELD: Duration = Duration::from_millis(100);

/// Legacy suffix marking a pin that was not finalised by an older publisher.
const IN_FLIGHT_SUFFIX: &str = "~new";

/// The temporary name protecting a fresh pin while stale pins are removed.
#[must_use]
pub fn in_flight_pin_name(name: &str) -> String {
    format!("{name}{IN_FLIGHT_SUFFIX}")
}

fn stale_pins(pins: Vec<String>, protected_cid: &str) -> Vec<String> {
    pins.into_iter()
        .filter(|cid| cid != protected_cid)
        .collect()
}

/// A fully confirmed pin that must never be removed by a cleanup job.
#[derive(Clone, Debug)]
pub struct PinCleanupRequest {
    pub kubo_url: String,
    pub name: String,
    pub protected_cid: String,
    pub cleanup_local: bool,
    pub remote_service: Option<String>,
}

#[derive(Clone, Debug, Eq)]
struct PinCleanupKey {
    kubo_url: String,
    name: String,
    cleanup_local: bool,
    remote_service: Option<String>,
}

impl PartialEq for PinCleanupKey {
    fn eq(&self, other: &Self) -> bool {
        self.kubo_url == other.kubo_url
            && self.name == other.name
            && self.cleanup_local == other.cleanup_local
            && self.remote_service == other.remote_service
    }
}

impl Hash for PinCleanupKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kubo_url.hash(state);
        self.name.hash(state);
        self.cleanup_local.hash(state);
        self.remote_service.hash(state);
    }
}

impl From<&PinCleanupRequest> for PinCleanupKey {
    fn from(request: &PinCleanupRequest) -> Self {
        Self {
            kubo_url: request.kubo_url.clone(),
            name: request.name.clone(),
            cleanup_local: request.cleanup_local,
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
    /// Returns the process-wide detached scheduler used by canonical publishers.
    #[must_use]
    pub fn global() -> &'static Self {
        static SCHEDULER: OnceLock<PinCleanupScheduler> = OnceLock::new();
        SCHEDULER.get_or_init(Self::new)
    }

    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_QUEUE_CAPACITY)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (wake, receiver) = mpsc::channel(capacity);
        tokio::spawn(run_cleanup_worker(
            Arc::clone(&pending),
            wake.clone(),
            receiver,
        ));
        Self { pending, wake }
    }

    /// Queue cleanup without awaiting Kubo or queue capacity.
    ///
    /// Returns `false` when the bounded queue is full or its worker has ended.
    pub fn schedule(&self, request: PinCleanupRequest) -> bool {
        let key = PinCleanupKey::from(&request);
        let mut pending = self.pending.lock().expect("pin cleanup scheduler poisoned");
        if let std::collections::hash_map::Entry::Occupied(mut entry) = pending.entry(key.clone()) {
            entry.insert(request);
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

/// Schedule best-effort removal of all local recursive pins with this exact
/// name, keeping only the current CID.
///
/// Pin the current CID under [`in_flight_pin_name`] first; the worker removes
/// every stale pin under both names and only then renames the surviving pin
/// to the requested name. An interrupted run leaves the in-flight pin intact,
/// so the data stays protected and the unfinished state is visible.
///
/// The function returns immediately; the detached worker re-lists and removes
/// until no stale pins remain. A full queue drops this pass and a later
/// publication may schedule another.
pub fn delete_local_pins_named_in_background(
    kubo_url: impl Into<String>,
    name: impl Into<String>,
    protected_cid: impl Into<String>,
) -> bool {
    PinCleanupScheduler::global().schedule(PinCleanupRequest {
        kubo_url: kubo_url.into(),
        name: name.into(),
        protected_cid: protected_cid.into(),
        cleanup_local: true,
        remote_service: None,
    })
}

/// Schedule best-effort removal of all remote pins with this exact name,
/// keeping only the current CID.
///
/// Also migrates pins left under the legacy in-flight name. Prefer
/// [`remote_pin_replace_named`], which pins the current CID and schedules this
/// cleanup in one call. This does not remove local pins.
pub fn delete_remote_pins_named_in_background(
    kubo_url: impl Into<String>,
    service: impl Into<String>,
    name: impl Into<String>,
    protected_cid: impl Into<String>,
) -> bool {
    PinCleanupScheduler::global().schedule(PinCleanupRequest {
        kubo_url: kubo_url.into(),
        name: name.into(),
        protected_cid: protected_cid.into(),
        cleanup_local: false,
        remote_service: Some(service.into()),
    })
}

/// Pin `cid` on the remote service and schedule best-effort replacement of
/// stale pins with this name.
///
/// With `overwrite` the fresh pin is added under the requested name before the
/// background worker removes stale CIDs with that exact name. Returns whether
/// cleanup was scheduled.
pub async fn remote_pin_replace_named(
    kubo_url: &str,
    service: &str,
    name: &str,
    cid: &str,
    overwrite: bool,
) -> anyhow::Result<bool> {
    crate::kubo::kubo::remote_pin_add_named(kubo_url, service, cid, name).await?;
    Ok(overwrite && delete_remote_pins_named_in_background(kubo_url, service, name, cid))
}

async fn run_cleanup_worker(
    pending: Arc<Mutex<HashMap<PinCleanupKey, PinCleanupRequest>>>,
    wake: mpsc::Sender<PinCleanupKey>,
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
        if cleanup_one_batch(&request).await {
            let should_requeue = {
                let mut pending = pending.lock().expect("pin cleanup scheduler poisoned");
                if pending.contains_key(&key) {
                    false
                } else {
                    pending.insert(key.clone(), request);
                    true
                }
            };
            if should_requeue {
                tokio::time::sleep(CLEANUP_YIELD).await;
                if let Err(error) = wake.try_send(key) {
                    debug!(error = %error, "dropping delayed pin cleanup batch");
                }
            }
        }
    }
}

async fn cleanup_one_batch(request: &PinCleanupRequest) -> bool {
    let local_more = if request.cleanup_local {
        cleanup_local_pass(request).await
    } else {
        false
    };
    let remote_more = if request.remote_service.is_some() {
        cleanup_remote_pass(request).await
    } else {
        false
    };
    local_more || remote_more
}

async fn cleanup_local_pass(request: &PinCleanupRequest) -> bool {
    let temp_name = in_flight_pin_name(&request.name);
    let final_pins = match crate::kubo::kubo::list_named_recursive_pins(
        &request.kubo_url,
        &request.name,
    )
    .await
    {
        Ok(pins) => pins,
        Err(error) => {
            warn!(name = %request.name, error = %error, "local old-pin lookup failed");
            return false;
        }
    };
    let temp_pins =
        match crate::kubo::kubo::list_named_recursive_pins(&request.kubo_url, &temp_name).await {
            Ok(pins) => pins,
            Err(error) => {
                warn!(name = %temp_name, error = %error, "local in-flight pin lookup failed");
                return false;
            }
        };

    let mut all_pins = final_pins.clone();
    all_pins.extend(temp_pins);
    let stale = stale_pins(all_pins, &request.protected_cid);
    if !stale.is_empty() {
        let mut removed_any = false;
        for cid in stale {
            match crate::kubo::kubo::pin_rm(&request.kubo_url, &cid).await {
                Ok(()) => removed_any = true,
                Err(error) => {
                    warn!(name = %request.name, cid = %cid, error = %error, "local old-pin cleanup failed");
                }
            }
        }
        // Re-list only while we make progress, so a broken Kubo cannot spin us.
        return removed_any;
    }

    // Clean: finalise by renaming the in-flight pin to the requested name.
    // On failure the in-flight pin still protects the data for a later pass.
    if !final_pins.iter().any(|cid| cid == &request.protected_cid) {
        if let Err(error) = crate::kubo::kubo::pin_add_named(
            &request.kubo_url,
            &request.protected_cid,
            &request.name,
        )
        .await
        {
            warn!(name = %request.name, cid = %request.protected_cid, error = %error, "local pin finalisation failed");
        }
    }
    false
}

async fn cleanup_remote_pass(request: &PinCleanupRequest) -> bool {
    let Some(service) = request.remote_service.as_deref() else {
        return false;
    };
    let temp_name = in_flight_pin_name(&request.name);
    let final_pins = match crate::kubo::kubo::list_named_remote_pins(
        &request.kubo_url,
        service,
        &request.name,
    )
    .await
    {
        Ok(pins) => pins,
        Err(error) => {
            warn!(name = %request.name, service, error = %error, "remote old-pin lookup failed");
            return false;
        }
    };
    let temp_pins = match crate::kubo::kubo::list_named_remote_pins(
        &request.kubo_url,
        service,
        &temp_name,
    )
    .await
    {
        Ok(pins) => pins,
        Err(error) => {
            warn!(name = %temp_name, service, error = %error, "remote in-flight pin lookup failed");
            return false;
        }
    };

    let stale_final = stale_pins(final_pins.clone(), &request.protected_cid);
    let stale_temp = stale_pins(temp_pins.clone(), &request.protected_cid);
    if !stale_final.is_empty() || !stale_temp.is_empty() {
        let mut removed_any = false;
        for (cid, pin_name) in stale_final
            .iter()
            .map(|cid| (cid, request.name.as_str()))
            .chain(stale_temp.iter().map(|cid| (cid, temp_name.as_str())))
        {
            match crate::kubo::kubo::remote_pin_rm_named(&request.kubo_url, service, cid, pin_name)
                .await
            {
                Ok(()) => removed_any = true,
                Err(error) => {
                    warn!(name = %pin_name, service, cid = %cid, error = %error, "remote old-pin cleanup failed");
                }
            }
        }
        // Re-list only while we make progress, so a broken service cannot spin us.
        return removed_any;
    }

    // Migrate pins stranded by the old in-flight protocol. Remote services
    // commonly reject adding the same CID under a second name, so remove the
    // temporary record before recreating it under the requested name.
    if temp_pins.iter().any(|cid| cid == &request.protected_cid) {
        if !final_pins.iter().any(|cid| cid == &request.protected_cid) {
            if let Err(error) = crate::kubo::kubo::remote_pin_rm_named(
                &request.kubo_url,
                service,
                &request.protected_cid,
                &temp_name,
            )
            .await
            {
                warn!(name = %temp_name, service, cid = %request.protected_cid, error = %error, "legacy in-flight pin removal failed");
                return false;
            }
            if let Err(error) = crate::kubo::kubo::remote_pin_add_named(
                &request.kubo_url,
                service,
                &request.protected_cid,
                &request.name,
            )
            .await
            {
                warn!(name = %request.name, service, cid = %request.protected_cid, error = %error, "legacy pin migration failed");
            }
        } else if let Err(error) = crate::kubo::kubo::remote_pin_rm_named(
            &request.kubo_url,
            service,
            &request.protected_cid,
            &temp_name,
        )
        .await
        {
            warn!(name = %temp_name, service, cid = %request.protected_cid, error = %error, "legacy in-flight pin removal failed");
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::stale_pins;

    #[test]
    fn stale_pins_protects_current_cid() {
        let stale = stale_pins(
            vec![
                "old-a".to_string(),
                "current".to_string(),
                "old-b".to_string(),
                "old-c".to_string(),
            ],
            "current",
        );

        assert_eq!(stale, ["old-a", "old-b", "old-c"]);
    }

    #[test]
    fn stale_pins_returns_empty_when_only_current_remains() {
        let stale = stale_pins(vec!["current".to_string()], "current");

        assert!(stale.is_empty());
    }
}
