//! HTTP gateway pool for read-only IPFS/IPNS access.
//!
//! [`GatewayPool`] owns the gateway list, hedged failover, per-gateway
//! cooldowns and request timeouts. It knows nothing about DID documents,
//! caching, or publishing — higher layers compose it.

use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;

use futures_util::future::{select, Either};
use futures_util::stream::{FuturesUnordered, StreamExt};
use web_time::{Duration, Instant};

pub(crate) const LOCALHOST_GATEWAY: &str = "http://127.0.0.1:8080/";
pub(crate) const DEFAULT_PUBLIC_GATEWAYS: [&str; 1] = ["https://ipfs.io/"];

/// Base cooldown after a gateway failure. Escalates Fibonacci-style
/// (base × 1, 1, 2, 3, 5, …) per consecutive failure; resets on success.
const DEFAULT_BASE_COOLDOWN: Duration = Duration::from_secs(5);
/// Upper bound for the escalated per-gateway cooldown.
const MAX_COOLDOWN: Duration = Duration::from_mins(5);
/// Fibonacci escalation stops growing after this many failures (fib(12) = 144).
const MAX_FIBONACCI_STEPS: u32 = 12;
/// How long a pending attempt may stay unanswered before the next gateway
/// is raced against it.
const HEDGE_DELAY: Duration = Duration::from_secs(2);
/// Hard deadline for one whole fetch/resolve across all gateways.
const TOTAL_DEADLINE: Duration = Duration::from_mins(1);
/// Default per-request timeout, covering connection and body transfer.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

/// Per-gateway failure tracking for cooldown escalation.
#[derive(Default)]
struct GatewayHealth {
    consecutive_failures: u32,
    blocked_until: Option<Instant>,
}

/// Failed attempt outcome. `penalise` is false for content-level rejections
/// (parse failures, deadline skips) that say nothing about gateway health.
struct AttemptError {
    detail: String,
    penalise: bool,
}

impl AttemptError {
    fn gateway(detail: String) -> Self {
        Self {
            detail,
            penalise: true,
        }
    }

    fn content(detail: String) -> Self {
        Self {
            detail,
            penalise: false,
        }
    }
}

enum RaceStep<T> {
    Completed(usize, Result<T, AttemptError>),
    StartNext,
}

/// Ordered pool of IPFS HTTP gateways with hedged failover and per-gateway
/// Fibonacci cooldowns.
///
/// Read-only: fetches content and resolves IPNS paths. Publishing, pinning
/// and key management belong to the Kubo client (`crate::kubo`), never here.
pub struct GatewayPool {
    gateways: Vec<String>,
    client: reqwest::Client,
    base_cooldown: Duration,
    /// Per-request timeout. `None` → the built-in default.
    request_timeout: Mutex<Option<Duration>>,
    /// Parallel to `gateways`.
    health: Mutex<Vec<GatewayHealth>>,
}

impl Default for GatewayPool {
    /// Build a local-first pool for development and native runtimes.
    fn default() -> Self {
        let mut gateways = Vec::new();
        push_gateway(&mut gateways, LOCALHOST_GATEWAY);
        push_default_public_gateways(&mut gateways);
        Self::from_gateway_list(gateways)
    }
}

impl GatewayPool {
    /// Build a pool from exactly the caller-provided gateways.
    ///
    /// No localhost or public fallback gateways are added implicitly. Empty
    /// entries are ignored after trimming, and the resulting list must contain
    /// at least one gateway.
    pub fn from_gateways<I, S>(gateways: I) -> crate::error::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = Vec::new();
        for gateway in gateways {
            let gateway = gateway.as_ref();
            if !gateway.trim().is_empty() {
                push_gateway(&mut list, gateway);
            }
        }
        if list.is_empty() {
            return Err(crate::error::Error::InvalidTransport(
                "gateway list must not be empty".to_string(),
            ));
        }
        Ok(Self::from_gateway_list(list))
    }

    /// Build a public-gateway pool with no localhost probing.
    #[must_use]
    pub fn public_default() -> Self {
        let mut gateways = Vec::new();
        push_default_public_gateways(&mut gateways);
        Self::from_gateway_list(gateways)
    }

    /// Build a pool using the caller-provided primary gateway followed by
    /// the standard public fallbacks. Localhost is used only if `gateway_url`
    /// itself points at localhost.
    #[must_use]
    pub fn new(gateway_url: impl Into<String>) -> Self {
        let mut gateways = Vec::new();
        push_gateway(&mut gateways, &gateway_url.into());
        push_default_public_gateways(&mut gateways);
        Self::from_gateway_list(gateways)
    }

    /// Build a local-first pool: localhost, then the caller-provided primary
    /// gateway, then the standard public fallbacks.
    #[must_use]
    pub fn local_first(gateway_url: impl Into<String>) -> Self {
        let mut gateways = Vec::new();
        push_gateway(&mut gateways, LOCALHOST_GATEWAY);
        push_gateway(&mut gateways, &gateway_url.into());
        push_default_public_gateways(&mut gateways);
        Self::from_gateway_list(gateways)
    }

    fn from_gateway_list(gateways: Vec<String>) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        #[cfg(target_arch = "wasm32")]
        // reqwest's wasm backend delegates to browser fetch, whose default
        // redirect mode is `follow`; the wasm ClientBuilder does not expose a
        // redirect policy knob.
        let client = reqwest::Client::builder()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let health = gateways.iter().map(|_| GatewayHealth::default()).collect();
        Self {
            gateways,
            client,
            base_cooldown: DEFAULT_BASE_COOLDOWN,
            request_timeout: Mutex::new(None),
            health: Mutex::new(health),
        }
    }

    /// The ordered gateway URLs this pool will try.
    #[must_use]
    pub fn gateways(&self) -> &[String] {
        &self.gateways
    }

    /// Override the base cooldown applied after a gateway failure.
    /// The cooldown escalates Fibonacci-style per consecutive failure and
    /// resets on success. `Duration::ZERO` disables cooldowns entirely.
    #[must_use]
    pub fn with_base_cooldown(mut self, cooldown: Duration) -> Self {
        self.base_cooldown = cooldown;
        self
    }

    /// Override the per-request timeout (default 6 seconds). The timeout
    /// covers the whole request, connection through body transfer, and is
    /// clamped to the time remaining before the operation deadline.
    #[must_use]
    pub fn with_request_timeout(self, timeout: Duration) -> Self {
        self.set_request_timeout(Some(timeout));
        self
    }

    /// Update the per-request timeout at runtime.
    /// Pass `None` to revert to the 6-second built-in default.
    pub fn set_request_timeout(&self, timeout: Option<Duration>) {
        if let Ok(mut t) = self.request_timeout.lock() {
            *t = timeout;
        }
    }

    /// GET `path` from the gateway pool until `parse` accepts a body.
    ///
    /// Gateways are tried in cooldown-filtered order, hedged: a pending
    /// attempt that has not answered within `HEDGE_DELAY` gets the next
    /// gateway raced against it and the first parsed success wins. Failing
    /// gateways earn an escalating Fibonacci cooldown; the whole operation
    /// is bounded by `TOTAL_DEADLINE`. On total failure the per-gateway
    /// errors are joined into one string for the caller to wrap.
    pub async fn fetch<T>(
        &self,
        path: &str,
        accept: Option<&str>,
        parse: impl Fn(&[u8]) -> std::result::Result<T, String>,
    ) -> std::result::Result<T, String> {
        let deadline = Instant::now() + TOTAL_DEADLINE;
        let parse = &parse;
        self.race_gateways(move |index| self.attempt_fetch(index, path, accept, parse, deadline))
            .await
            .map_err(|detail| format!("all gateways failed: {detail}"))
    }

    /// Fetch raw bytes for `path` (e.g. `/ipfs/<cid>`) with gateway failover.
    pub async fn fetch_bytes(
        &self,
        path: &str,
        accept: Option<&str>,
    ) -> std::result::Result<Vec<u8>, String> {
        self.fetch(path, accept, |body| Ok(body.to_vec())).await
    }

    /// Resolve an `/ipns/<name>` reference to its current `/ipfs/<cid>` path.
    ///
    /// Reads only gateway response metadata, never the referenced content
    /// body. Gateways commonly expose the resolved content path in
    /// `X-Ipfs-Path`; redirects to `/ipfs/...` are accepted as a fallback.
    /// Uses the same hedged failover and cooldowns as [`GatewayPool::fetch`].
    pub async fn resolve_ipns_path(&self, path: &str) -> crate::error::Result<String> {
        if !path.starts_with("/ipns/") || path.len() <= "/ipns/".len() {
            return Err(crate::error::Error::IpnsResolution {
                path: path.to_string(),
                detail: "expected a non-empty /ipns/<name> path".to_string(),
            });
        }

        let deadline = Instant::now() + TOTAL_DEADLINE;
        self.race_gateways(move |index| self.attempt_resolve(index, path, deadline))
            .await
            .map_err(|detail| crate::error::Error::IpnsResolution {
                path: path.to_string(),
                detail,
            })
    }

    /// Run `attempt` against the gateways with staggered hedging: the first
    /// candidate starts immediately, and while any attempt is pending the
    /// next candidate joins the race after [`HEDGE_DELAY`] or as soon as an
    /// attempt fails. First success wins; losers are dropped (cancelled).
    async fn race_gateways<T, F, Fut>(&self, attempt: F) -> std::result::Result<T, String>
    where
        F: Fn(usize) -> Fut,
        Fut: Future<Output = (usize, std::result::Result<T, AttemptError>)>,
    {
        let mut errors = Vec::new();
        let order = self.gateway_order(Instant::now(), &mut errors);

        let mut in_flight = FuturesUnordered::new();
        let mut candidates = order.into_iter();
        let mut next_candidate = candidates.next();

        loop {
            if in_flight.is_empty() {
                match next_candidate.take() {
                    Some(index) => {
                        in_flight.push(attempt(index));
                        next_candidate = candidates.next();
                        continue;
                    }
                    None => break,
                }
            }

            let step = if next_candidate.is_some() {
                let completion = in_flight.next();
                match select(pin!(completion), pin!(hedge_sleep(HEDGE_DELAY))).await {
                    Either::Left((Some((index, result)), _)) => RaceStep::Completed(index, result),
                    Either::Left((None, _)) | Either::Right(_) => RaceStep::StartNext,
                }
            } else {
                match in_flight.next().await {
                    Some((index, result)) => RaceStep::Completed(index, result),
                    None => break,
                }
            };

            match step {
                RaceStep::Completed(index, Ok(value)) => {
                    self.record_success(index);
                    return Ok(value);
                }
                RaceStep::Completed(index, Err(error)) => {
                    if error.penalise {
                        self.record_failure(index);
                    }
                    errors.push(error.detail);
                    if let Some(index) = next_candidate.take() {
                        in_flight.push(attempt(index));
                        next_candidate = candidates.next();
                    }
                }
                RaceStep::StartNext => {
                    if let Some(index) = next_candidate.take() {
                        in_flight.push(attempt(index));
                        next_candidate = candidates.next();
                    }
                }
            }
        }

        Err(format!(
            "all {} gateways failed: {}",
            errors.len(),
            errors.join("; ")
        ))
    }

    async fn attempt_fetch<T, P>(
        &self,
        index: usize,
        path: &str,
        accept: Option<&str>,
        parse: &P,
        deadline: Instant,
    ) -> (usize, std::result::Result<T, AttemptError>)
    where
        P: Fn(&[u8]) -> std::result::Result<T, String>,
    {
        let url = gateway_url_for_path(&self.gateways[index], path);
        let Some(timeout) = self.remaining_timeout(deadline) else {
            return (
                index,
                Err(AttemptError::content(format!(
                    "{url} -> skipped (deadline exceeded)"
                ))),
            );
        };

        let mut request = self.client.get(&url).timeout(timeout);
        if let Some(accept) = accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }

        let response = match request.send().await {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                return (
                    index,
                    Err(AttemptError::gateway(format!(
                        "{url} -> HTTP {}",
                        response.status()
                    ))),
                );
            }
            Err(error) => {
                return (
                    index,
                    Err(AttemptError::gateway(format!("{url} -> {error}"))),
                );
            }
        };

        let body = match response.bytes().await {
            Ok(body) => body,
            Err(error) => {
                return (
                    index,
                    Err(AttemptError::gateway(format!("{url} -> {error}"))),
                );
            }
        };

        match parse(&body) {
            Ok(value) => (index, Ok(value)),
            Err(detail) => (
                index,
                Err(AttemptError::content(format!("{url} -> {detail}"))),
            ),
        }
    }

    async fn attempt_resolve(
        &self,
        index: usize,
        path: &str,
        deadline: Instant,
    ) -> (usize, std::result::Result<String, AttemptError>) {
        let url = gateway_url_for_path(&self.gateways[index], path);
        let Some(timeout) = self.remaining_timeout(deadline) else {
            return (
                index,
                Err(AttemptError::content(format!(
                    "{url} -> skipped (deadline exceeded)"
                ))),
            );
        };

        let response = match self.client.get(&url).timeout(timeout).send().await {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                return (
                    index,
                    Err(AttemptError::gateway(format!(
                        "{url} -> HTTP {}",
                        response.status()
                    ))),
                );
            }
            Err(error) => {
                return (
                    index,
                    Err(AttemptError::gateway(format!("{url} -> {error}"))),
                );
            }
        };

        let header_path = response
            .headers()
            .get("x-ipfs-path")
            .and_then(|value| value.to_str().ok());
        if let Some(resolved) = resolved_ipfs_path(header_path, response.url().path()) {
            return (index, Ok(resolved));
        }

        (
            index,
            Err(AttemptError::content(format!(
                "{url} -> gateway did not expose a resolved /ipfs path"
            ))),
        )
    }

    /// Per-request timeout clamped to the time left before `deadline`.
    /// `None` when the deadline has already passed.
    fn remaining_timeout(&self, deadline: Instant) -> Option<Duration> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let configured = self
            .request_timeout
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT);
        Some(configured.min(remaining))
    }

    /// Gateway indices to try, skipping those in cooldown. If every gateway
    /// is in cooldown, all are returned so a fetch never dead-ends.
    fn gateway_order(&self, now: Instant, errors: &mut Vec<String>) -> Vec<usize> {
        let Ok(health) = self.health.lock() else {
            return (0..self.gateways.len()).collect();
        };
        let mut available = Vec::new();
        let mut skipped = Vec::new();
        for (index, entry) in health.iter().enumerate() {
            if entry.blocked_until.is_none_or(|until| until <= now) {
                available.push(index);
            } else {
                skipped.push(index);
            }
        }
        if available.is_empty() {
            return (0..self.gateways.len()).collect();
        }
        for index in skipped {
            errors.push(format!("{} -> skipped (cooldown)", self.gateways[index]));
        }
        available
    }

    fn record_success(&self, index: usize) {
        if let Ok(mut health) = self.health.lock() {
            if let Some(entry) = health.get_mut(index) {
                *entry = GatewayHealth::default();
            }
        }
    }

    fn record_failure(&self, index: usize) {
        if let Ok(mut health) = self.health.lock() {
            if let Some(entry) = health.get_mut(index) {
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                let cooldown = fibonacci_cooldown(self.base_cooldown, entry.consecutive_failures);
                entry.blocked_until = Some(Instant::now() + cooldown);
            }
        }
    }
}

/// `base × fib(n)` capped at [`MAX_COOLDOWN`]: base × 1, 1, 2, 3, 5, 8, …
fn fibonacci_cooldown(base: Duration, consecutive_failures: u32) -> Duration {
    let steps = consecutive_failures.clamp(1, MAX_FIBONACCI_STEPS);
    let (mut previous, mut current) = (0u32, 1u32);
    for _ in 1..steps {
        let next = previous + current;
        previous = current;
        current = next;
    }
    base.saturating_mul(current).min(MAX_COOLDOWN)
}

/// Wasm-safe sleep used only to stagger hedged gateway attempts.
async fn hedge_sleep(duration: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(duration).await;
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::TimeoutFuture::new(
        u32::try_from(duration.as_millis()).unwrap_or(u32::MAX),
    )
    .await;
}

fn normalize_gateway_url(input: &str) -> String {
    let mut url = input.trim().to_string();
    if !url.ends_with('/') {
        url.push('/');
    }
    url
}

fn push_gateway(gateways: &mut Vec<String>, candidate: &str) {
    let normalized = normalize_gateway_url(candidate);
    if !gateways.iter().any(|g| g.eq_ignore_ascii_case(&normalized)) {
        gateways.push(normalized);
    }
}

fn push_default_public_gateways(gateways: &mut Vec<String>) {
    for fallback in DEFAULT_PUBLIC_GATEWAYS {
        push_gateway(gateways, fallback);
    }
}

/// Build the URL to fetch `path` from `gateway`.
/// Path gateways use the plain path form: `{gateway}ipfs/{cid}` and
/// `{gateway}ipns/{name}`.
fn gateway_url_for_path(gateway: &str, path: &str) -> String {
    format!("{}{}", gateway, path.trim_start_matches('/'))
}

fn resolved_ipfs_path(header_path: Option<&str>, final_path: &str) -> Option<String> {
    header_path
        .into_iter()
        .chain(std::iter::once(final_path))
        .find_map(|path| {
            path.strip_prefix("/ipfs/")
                .map(|cid| format!("/ipfs/{cid}"))
        })
}

#[cfg(test)]
mod tests {
    use super::{
        fibonacci_cooldown, gateway_url_for_path, normalize_gateway_url, push_gateway,
        resolved_ipfs_path, GatewayPool, MAX_COOLDOWN,
    };
    use web_time::{Duration, Instant};

    #[test]
    fn resolved_ipfs_path_prefers_gateway_header() {
        assert_eq!(
            resolved_ipfs_path(Some("/ipfs/bafyheader"), "/ipfs/bafyredirect"),
            Some("/ipfs/bafyheader".to_string())
        );
        assert_eq!(
            resolved_ipfs_path(None, "/ipfs/bafyredirect"),
            Some("/ipfs/bafyredirect".to_string())
        );
        assert_eq!(resolved_ipfs_path(None, "/ipns/k51name"), None);
    }

    #[test]
    fn gateway_url_for_path_keeps_path_form() {
        assert_eq!(
            gateway_url_for_path("https://ipfs.io/", "/ipfs/bafycid"),
            "https://ipfs.io/ipfs/bafycid"
        );
        assert_eq!(
            gateway_url_for_path("https://ipfs.io/", "/ipns/k51abc"),
            "https://ipfs.io/ipns/k51abc"
        );
        assert_eq!(
            gateway_url_for_path("http://127.0.0.1:8080/", "/ipns/k51abc"),
            "http://127.0.0.1:8080/ipns/k51abc"
        );
    }

    #[test]
    fn normalize_gateway_url_adds_missing_trailing_slash() {
        assert_eq!(
            normalize_gateway_url("https://dweb.link"),
            "https://dweb.link/"
        );
        assert_eq!(
            normalize_gateway_url("https://dweb.link/"),
            "https://dweb.link/"
        );
        assert_eq!(
            normalize_gateway_url("  https://dweb.link  "),
            "https://dweb.link/"
        );
    }

    #[test]
    fn push_gateway_deduplicates_case_insensitively() {
        let mut gateways = Vec::new();
        push_gateway(&mut gateways, "https://dweb.link/");
        push_gateway(&mut gateways, "https://dweb.link/"); // exact duplicate
        push_gateway(&mut gateways, "https://dweb.link"); // no trailing slash
        assert_eq!(gateways.len(), 1, "duplicates must not be added");
    }

    #[test]
    fn default_is_local_first() {
        let pool = GatewayPool::default();
        assert_eq!(
            pool.gateways(),
            [
                "http://127.0.0.1:8080/".to_string(),
                "https://ipfs.io/".to_string(),
            ]
        );
    }

    #[test]
    fn public_default_never_includes_localhost() {
        let pool = GatewayPool::public_default();
        assert_eq!(pool.gateways(), ["https://ipfs.io/".to_string()]);
    }

    #[test]
    fn new_uses_primary_then_public_fallbacks_without_hidden_localhost() {
        let pool = GatewayPool::new("https://example.test/ipfs");
        assert_eq!(
            pool.gateways(),
            [
                "https://example.test/ipfs/".to_string(),
                "https://ipfs.io/".to_string(),
            ]
        );
    }

    #[test]
    fn local_first_puts_localhost_before_primary() {
        let pool = GatewayPool::local_first("https://example.test/");
        assert_eq!(
            pool.gateways(),
            [
                "http://127.0.0.1:8080/".to_string(),
                "https://example.test/".to_string(),
                "https://ipfs.io/".to_string(),
            ]
        );
    }

    #[test]
    fn from_gateways_uses_exact_deduplicated_list() {
        let pool = GatewayPool::from_gateways([
            "https://example.test/ipfs",
            "",
            "https://example.test/ipfs/",
            "http://localhost:8881/",
        ])
        .expect("gateway list");
        assert_eq!(
            pool.gateways(),
            [
                "https://example.test/ipfs/".to_string(),
                "http://localhost:8881/".to_string(),
            ]
        );
    }

    #[test]
    fn from_gateways_rejects_empty_lists() {
        let result = GatewayPool::from_gateways(["", "  "]);
        assert!(result
            .err()
            .is_some_and(|err| err.to_string().contains("gateway list must not be empty")));
    }

    #[test]
    fn fibonacci_cooldown_escalates_and_caps() {
        let base = Duration::from_secs(5);
        assert_eq!(fibonacci_cooldown(base, 1), Duration::from_secs(5));
        assert_eq!(fibonacci_cooldown(base, 2), Duration::from_secs(5));
        assert_eq!(fibonacci_cooldown(base, 3), Duration::from_secs(10));
        assert_eq!(fibonacci_cooldown(base, 4), Duration::from_secs(15));
        assert_eq!(fibonacci_cooldown(base, 5), Duration::from_secs(25));
        assert_eq!(fibonacci_cooldown(base, 6), Duration::from_secs(40));
        assert_eq!(fibonacci_cooldown(base, 100), MAX_COOLDOWN);
        assert_eq!(fibonacci_cooldown(Duration::ZERO, 7), Duration::ZERO);
    }

    #[test]
    fn record_failure_blocks_gateway_and_success_clears_it() {
        let pool = GatewayPool::default();
        let mut errors = Vec::new();

        assert_eq!(
            pool.gateway_order(Instant::now(), &mut errors),
            vec![0, 1],
            "all gateways available initially"
        );

        pool.record_failure(0);
        errors.clear();
        assert_eq!(
            pool.gateway_order(Instant::now(), &mut errors),
            vec![1],
            "failed gateway must be skipped during cooldown"
        );
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("skipped (cooldown)"));

        pool.record_success(0);
        errors.clear();
        assert_eq!(
            pool.gateway_order(Instant::now(), &mut errors),
            vec![0, 1],
            "success must clear the cooldown"
        );
        assert!(errors.is_empty());
    }

    #[test]
    fn gateway_order_falls_back_to_all_when_everything_is_blocked() {
        let pool = GatewayPool::default();
        for index in 0..pool.gateways().len() {
            pool.record_failure(index);
        }
        let mut errors = Vec::new();
        assert_eq!(
            pool.gateway_order(Instant::now(), &mut errors),
            vec![0, 1],
            "a fetch must never dead-end on cooldowns alone"
        );
        assert!(errors.is_empty());
    }

    #[test]
    fn zero_base_cooldown_disables_blocking() {
        let pool = GatewayPool::default().with_base_cooldown(Duration::ZERO);
        pool.record_failure(0);
        let mut errors = Vec::new();
        assert_eq!(
            pool.gateway_order(Instant::now(), &mut errors),
            vec![0, 1],
            "zero base cooldown must never block a gateway"
        );
    }
}
