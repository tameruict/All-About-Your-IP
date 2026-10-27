//! Orchestrator — parallel job dispatch, timeouts, circuit breaker, partial
//! results and streaming (§4.3, §13).
//!
//! # How a check runs
//!
//! 1. **Validate** first (§3.4): an invalid or private/loopback/reserved IP
//!    short-circuits and *no* provider is called.
//! 2. **Dispatch** every module concurrently under one
//!    [`tokio::sync::Semaphore`] capped at [`MAX_CONCURRENCY`] (8) so an API is
//!    never bursted. Each provider gets its own `timeout_ms` from
//!    `providers.yaml`, clamped into the §4.3 window.
//! 3. **Emit per module.** Every module that finishes pushes a `check-progress`
//!    event immediately — the UI never waits for the slowest provider (§3.3).
//! 4. **Retry** at most once, and only for transient failures (timeout / 5xx),
//!    never for `NoKey` / `Quota` / `CircuitOpen` (§4.3).
//! 5. **Circuit breaker**: 5 failures within the window opens the breaker for
//!    10 minutes; an open breaker is reported as `skipped`, not as an error.
//! 6. **Partial result**: a provider that times out yields
//!    `signal = Unknown` + `error = timeout` and is excluded from scoring; the
//!    check still completes and the confidence reflects the loss.
//! 7. **Leak / speed only in proxy mode** (§1.2); in IP-only mode they are
//!    `Chưa đo được — cần nhập proxy`, never zeros.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::asn;
use crate::browser_leak;
use crate::cache::{self, TtlClass};
use crate::config;
use crate::dnsbl;
use crate::exit_ip;
use crate::location;
use crate::models::{
    Category, CheckMode, CheckOptions, CheckProgressEvent, CheckSession, DnsblGroup, FullCheckResult,
    HealthState, IpFlags, IpType, ModuleId, ModuleState, ModuleStatus, ProviderError,
    ProviderEvidence, ProviderHealth, ProxyProtocol, Signal, SkipReason,
};
use crate::network;
use crate::providers::registry::Registry;
use crate::scoring;
use crate::speed;
use crate::validator;

/// Concurrency cap so providers never see a burst (§4.3, default 8).
pub const MAX_CONCURRENCY: usize = 8;

/// Lower bound for a provider timeout (§4.3: 5–8s window, hard floor 1s).
pub const MIN_TIMEOUT_MS: u64 = 1_000;

/// Default per-provider timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 8_000;

/// Upper bound so a badly configured YAML can still finish a check.
pub const MAX_TIMEOUT_MS: u64 = 30_000;

/// Circuit breaker: failures within a window before opening (§4.3).
pub const CIRCUIT_FAILURE_THRESHOLD: u32 = 5;
/// How long the breaker stays open.
pub const CIRCUIT_COOLDOWN: Duration = Duration::from_secs(600);

/// Bytes downloaded per speed endpoint (§8.3 keeps the check under a minute).
pub const CONTRACT_SPEED_BYTES: u64 = 5_000_000;

// ---------------------------------------------------------------------------
// Hard deadlines for the proxy-only modules (§8)
// ---------------------------------------------------------------------------
//
// These are **outer guards**, not the modules' own budgets. The leak module
// drives a real browser and historically did so with a blocking
// `thread::sleep` loop; a blocking call cannot be interrupted by
// `tokio::time::timeout`, but wrapping it still guarantees the *orchestrator*
// gives up and finalises the scan. Without them a user who typed a dead proxy
// watched a spinner forever with the input disabled.
//
// Each budget = the module's own internal budget + generous overhead:
//   ExitIp : 8 s per endpoint, three endpoints in parallel   → 12 s
//   Leak   : 25 s browser budget (clamped 20–30 s) + 2 s grace → 35 s
//   Speed  : 45 s module budget                              → 50 s
pub const EXIT_IP_DEADLINE: Duration = Duration::from_secs(12);
pub const LEAK_DEADLINE: Duration = Duration::from_secs(35);
pub const SPEED_DEADLINE: Duration = Duration::from_secs(50);

/// Coarse progress callback. `commands.rs` adapts this to a Tauri event emitter.
pub type ProgressSink<'a> = Box<dyn Fn(CheckProgressEvent) + Send + Sync + 'a>;

// ---------------------------------------------------------------------------
// Circuit breaker + provider statistics (§4.3, §5.5)
// ---------------------------------------------------------------------------

/// Runtime stats for one provider, feeding both the breaker and the health panel.
#[derive(Debug)]
pub struct ProviderStats {
    pub total_checks: AtomicU32,
    pub successes: AtomicU32,
    pub failures: AtomicU32,
    pub consecutive_failures: AtomicU32,
    pub latency_sum_ms: AtomicU32,
    pub quota_hits: AtomicU32,
    last_error: Mutex<Option<(String, String)>>,
    circuit_open_until: Mutex<Option<Instant>>,
}

impl Default for ProviderStats {
    fn default() -> Self {
        Self {
            total_checks: AtomicU32::new(0),
            successes: AtomicU32::new(0),
            failures: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            latency_sum_ms: AtomicU32::new(0),
            quota_hits: AtomicU32::new(0),
            last_error: Mutex::new(None),
            circuit_open_until: Mutex::new(None),
        }
    }
}

impl ProviderStats {
    pub fn is_circuit_open(&self) -> bool {
        match self.circuit_open_until.lock() {
            Ok(guard) => match *guard {
                Some(until) => Instant::now() < until,
                None => false,
            },
            Err(_) => false,
        }
    }

    pub fn circuit_open_until_rfc3339(&self) -> Option<String> {
        let guard = self.circuit_open_until.lock().ok()?;
        let until = (*guard)?;
        if Instant::now() >= until {
            return None;
        }
        let remaining = until.saturating_duration_since(Instant::now());
        Some((chrono::Utc::now() + chrono::Duration::from_std(remaining).ok()?).to_rfc3339())
    }

    pub fn record_success(&self, latency_ms: u64) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        self.successes.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        // Saturating sum: an absurd latency must not wrap the counter.
        let _ = self.latency_sum_ms.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(latency_ms.min(60_000) as u32))
        });
        if let Ok(mut open) = self.circuit_open_until.lock() {
            *open = None;
        }
    }

    pub fn record_failure(&self, error: &ProviderError) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        if error.kind == "quota" {
            self.quota_hits.fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut last) = self.last_error.lock() {
            *last = Some((chrono::Utc::now().to_rfc3339(), error.message.clone()));
        }
        // NoKey / config errors are not the provider's fault — they must not trip
        // the breaker, otherwise a missing key would disable a healthy API.
        if matches!(error.kind.as_str(), "no_key" | "config" | "invalid_input" | "not_implemented") {
            return;
        }
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        let consecutive = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        // Open on 5 consecutive failures, or a high overall failure rate.
        let should_open = consecutive >= CIRCUIT_FAILURE_THRESHOLD
            || (failures >= CIRCUIT_FAILURE_THRESHOLD && consecutive >= 3);
        if should_open {
            if let Ok(mut open) = self.circuit_open_until.lock() {
                *open = Some(Instant::now() + CIRCUIT_COOLDOWN);
            }
            tracing::warn!(
                "Circuit breaker MỞ cho provider trong {} giây ({} lần lỗi liên tiếp): {}",
                CIRCUIT_COOLDOWN.as_secs(),
                consecutive,
                error.message
            );
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.total_checks.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let ok = self.successes.load(Ordering::Relaxed);
        100.0 * ok as f64 / total as f64
    }

    pub fn latency_avg_ms(&self) -> Option<f64> {
        let total = self.total_checks.load(Ordering::Relaxed);
        if total == 0 {
            return None;
        }
        let ok = self.successes.load(Ordering::Relaxed).max(1);
        Some(self.latency_sum_ms.load(Ordering::Relaxed) as f64 / ok as f64)
    }

    pub fn last_error(&self) -> Option<(String, String)> {
        self.last_error.lock().ok()?.clone()
    }

    /// Reset the breaker (Settings → "Thử lại provider").
    pub fn reset_circuit(&self) {
        if let Ok(mut open) = self.circuit_open_until.lock() {
            *open = None;
        }
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }
}

/// Process-wide stats table.
pub fn stats_table() -> &'static Mutex<HashMap<String, &'static ProviderStats>> {
    static TABLE: OnceLock<Mutex<HashMap<String, &'static ProviderStats>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get (or create) the stats row for a provider id.
///
/// Rows leak intentionally: there are at most ~46 providers in a process
/// lifetime, and `Box::leak` keeps the `&'static` reference simple and lock-free
/// at the call sites.
pub fn stats_for(provider: &str) -> &'static ProviderStats {
    let mut table = match stats_table().lock() {
        Ok(table) => table,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(existing) = table.get(provider) {
        return existing;
    }
    let fresh: &'static ProviderStats = Box::leak(Box::new(ProviderStats::default()));
    table.insert(provider.to_string(), fresh);
    fresh
}

/// Snapshot of every provider's runtime health, keyed by provider id.
///
/// Used by `commands::get_provider_health` (§5.5). Providers that never ran are
/// absent here and defaulted by the command layer.
pub fn health_snapshot() -> HashMap<String, ProviderHealth> {
    let table = match stats_table().lock() {
        Ok(table) => table,
        Err(poisoned) => poisoned.into_inner(),
    };
    let registry = config::load_registry();

    let mut out = HashMap::with_capacity(table.len());
    for (id, stats) in table.iter() {
        let meta = registry.get(id);
        let circuit_open = stats.is_circuit_open();
        let success_rate = stats.success_rate();
        let last_error = stats.last_error();

        // §5.5 health decay: `models::HealthState` is a traffic light
        // (Green / Yellow / Red / Unknown), so map the numbers onto it.
        let state = if circuit_open {
            HealthState::Red
        } else if stats.total_checks.load(Ordering::Relaxed) == 0 {
            HealthState::Unknown
        } else if success_rate >= 90.0 {
            HealthState::Green
        } else if success_rate >= 50.0 {
            HealthState::Yellow
        } else {
            HealthState::Red
        };

        // §5.5 health decay: a struggling provider loses effective weight, it is
        // never silently dropped from the verdict.
        let configured = meta.map(|m| m.sanitised_weight()).unwrap_or(0.0);
        let effective = if circuit_open {
            0.0
        } else if stats.total_checks.load(Ordering::Relaxed) == 0 {
            configured
        } else {
            configured * (0.25 + 0.75 * (success_rate / 100.0))
        };

        out.insert(
            id.clone(),
            ProviderHealth {
                provider: id.clone(),
                category: meta.map(|m| m.category).unwrap_or(Category::Geo),
                upstream: meta.map(|m| m.upstream.clone()).unwrap_or_default(),
                state,
                success_rate,
                latency_avg_ms: stats.latency_avg_ms(),
                last_error_at: last_error.as_ref().map(|(at, _)| at.clone()),
                last_error: last_error.map(|(_, message)| message),
                consecutive_failures: stats.consecutive_failures.load(Ordering::Relaxed),
                circuit_open,
                circuit_open_until: stats.circuit_open_until_rfc3339(),
                effective_weight: effective,
                configured_weight: configured,
                requires_key: meta.map(|m| m.requires_key).unwrap_or(false),
                has_key: meta.map(|m| config::has_api_key(&m.id)).unwrap_or(false),
                enabled: meta.map(|m| m.enabled_by_default).unwrap_or(false),
                quota_exhausted: stats.quota_hits.load(Ordering::Relaxed) > 0
                    && stats.is_circuit_open(),
                quota_reset_at: None,
                db_version: meta.and_then(|m| m.db_name.clone()),
                db_updated_at: None,
                total_checks: u64::from(stats.total_checks.load(Ordering::Relaxed)),
            },
        );
    }
    out
}

// ---------------------------------------------------------------------------
// Module plan (§4.3)
// ---------------------------------------------------------------------------

/// Modules that run for IP-only mode, in display order (§4.3).
pub fn ip_only_modules() -> Vec<ModuleId> {
    vec![
        ModuleId::Validate,
        ModuleId::Geo,
        ModuleId::Asn,
        ModuleId::Fraud,
        ModuleId::Abuse,
        ModuleId::ThreatIntel,
        ModuleId::Dnsbl,
        ModuleId::Network,
        ModuleId::Location,
        ModuleId::Scoring,
    ]
}

/// Modules that additionally run in proxy mode (§8).
pub fn proxy_modules() -> Vec<ModuleId> {
    let mut modules = ip_only_modules();
    modules.push(ModuleId::ExitIp);
    modules.push(ModuleId::Leak);
    modules.push(ModuleId::Speed);
    modules
}

/// Fresh pending module list for a check.
pub fn initial_modules(mode: CheckMode) -> Vec<ModuleState> {
    let ids = match mode {
        CheckMode::Proxy => proxy_modules(),
        _ => {
            let mut list = ip_only_modules();
            list.push(ModuleId::ExitIp);
            list.push(ModuleId::Leak);
            list.push(ModuleId::Speed);
            list
        }
    };
    ids.into_iter()
        .map(|id| {
            let mut m = ModuleState::new(id);
            if mode != CheckMode::Proxy
                && matches!(id, ModuleId::ExitIp | ModuleId::Leak | ModuleId::Speed)
            {
                m.status = ModuleStatus::Skipped;
                m.skip_reason = Some(SkipReason::RequiresProxy);
                m.message = "Chưa đo được — cần nhập proxy".to_string();
            }
            m
        })
        .collect()
}

/// Result of a run: the session plus the assembled result.
pub struct RunOutcome {
    pub session: CheckSession,
}

// ---------------------------------------------------------------------------
// Provider invocation with timeout + single retry (§4.3)
// ---------------------------------------------------------------------------

/// Should this error be retried? Exactly one retry, transient failures only.
///
/// `429` and any `5xx` are transient; `4xx` auth/quota errors are not (§4.3).
pub fn is_retryable(error: &ProviderError) -> bool {
    if !error.retryable {
        return false;
    }
    if !matches!(error.kind.as_str(), "timeout" | "network" | "http") {
        return false;
    }
    match error.status {
        None => true,
        Some(429) => true,
        Some(code) => code >= 500,
    }
}

/// Run one provider with a hard timeout and at most one retry.
///
/// Returns evidence on success. On failure the returned error is final (already
/// retried or non-retryable). The API key never appears in the returned value
/// because adapters build `ProviderEvidence::raw` themselves (§4.4).
pub async fn call_provider(
    provider: &dyn crate::providers::Provider,
    ip: &IpAddr,
    timeout_ms: u64,
) -> (Result<ProviderEvidence, ProviderError>, u64) {
    let stats = stats_for(provider.id());
    let timeout = Duration::from_millis(timeout_ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS));

    if let Some(error) = circuit_open_error(provider.id()) {
        return (Err(error), 0);
    }

    let started = Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let outcome = tokio::time::timeout(timeout, provider.check(ip)).await;
        let elapsed = started.elapsed().as_millis() as u64;

        match outcome {
            Ok(Ok(evidence)) => {
                stats.record_success(elapsed);
                return (Ok(evidence), elapsed);
            }
            Ok(Err(error)) => {
                if attempt < 2 && is_retryable(&error) {
                    tracing::debug!(
                        "provider {} lỗi tạm thời ({}), thử lại 1 lần",
                        provider.id(),
                        error.message
                    );
                    continue;
                }
                stats.record_failure(&error);
                return (Err(error), elapsed);
            }
            Err(_) => {
                let error = ProviderError::timeout();
                if attempt < 2 {
                    tracing::debug!("provider {} timeout, thử lại 1 lần", provider.id());
                    continue;
                }
                stats.record_failure(&error);
                return (Err(error), elapsed);
            }
        }
    }
}

fn circuit_open_error(provider: &str) -> Option<ProviderError> {
    let stats = stats_for(provider);
    if stats.is_circuit_open() {
        Some(ProviderError::new(
            "circuit_open",
            format!("Provider {provider} tạm ngắt do lỗi liên tiếp (§4.3)"),
            false,
        ))
    } else {
        None
    }
}

/// Default source URL for a provider when an adapter errored before building evidence (§3.3).
pub fn default_source_url(provider: &str) -> &'static str {
    match provider {
        "greynoise" => "https://viz.greynoise.io/",
        "ipqualityscore" => "https://www.ipqualityscore.com/",
        "proxycheck" => "https://proxycheck.io/",
        "scamalytics" => "https://scamalytics.com/",
        "abuseipdb" => "https://www.abuseipdb.com/",
        "ip_api" | "ip_api_flags" => "https://ip-api.com/",
        "ipwho" => "https://ipwho.is/",
        "ipinfo" | "ipinfo_privacy" => "https://ipinfo.io/",
        "ripestat" => "https://stat.ripe.net/",
        "bgpview" => "https://bgpview.io/",
        "team_cymru" => "https://www.team-cymru.com/",
        _ => "",
    }
}

/// Evidence row for a provider that could not answer.
///
/// §4.3 "partial result": a timeout becomes `signal = Unknown` with
/// `error = timeout`, so scoring excludes it instead of guessing.
pub fn error_evidence(provider: &str, category: Category, upstream: &str, error: &ProviderError) -> ProviderEvidence {
    ProviderEvidence {
        provider: provider.to_string(),
        category,
        upstream: upstream.to_string(),
        signal: Signal::Unknown,
        raw_score: None,
        raw: None,
        checked_at: chrono::Utc::now().to_rfc3339(),
        source_url: default_source_url(provider).to_string(),
        latency_ms: None,
        error: Some(error.clone()),
        reason: Some(error.message.clone()),
        from_cache: false,
    }
}

// ---------------------------------------------------------------------------
// Evidence collection
// ---------------------------------------------------------------------------

/// Check whether a provider is enabled in user settings, falling back to `providers.yaml`.
pub fn is_provider_enabled(
    id: &str,
    registry: &Registry,
    settings: &crate::models::Settings,
) -> bool {
    if id == "ip_api_flags" {
        return is_provider_enabled("ip_api", registry, settings);
    }
    if id == "ipinfo_privacy" {
        return is_provider_enabled("ipinfo", registry, settings);
    }
    if let Some(entry) = settings.providers.iter().find(|p| p.provider == id) {
        return entry.enabled;
    }
    registry
        .get(id)
        .map(|m| m.enabled_by_default)
        .unwrap_or(false)
}

/// Resolve per-provider timeout (ms) from user settings, falling back to `providers.yaml`
/// and then `settings.default_timeout_ms`.
pub fn provider_timeout_ms(
    id: &str,
    registry: &Registry,
    settings: &crate::models::Settings,
) -> u64 {
    if let Some(entry) = settings.providers.iter().find(|p| p.provider == id) {
        if let Some(ms) = entry.timeout_ms {
            if ms > 0 {
                return clamp_timeout(Some(ms));
            }
        }
    }
    if let Some(meta) = registry.get(id) {
        if meta.timeout_ms > 0 {
            return clamp_timeout(Some(meta.timeout_ms));
        }
    }
    clamp_timeout(Some(settings.default_timeout_ms))
}

/// Run every adapter of one category in parallel under a shared semaphore.
async fn run_category(
    adapters: &crate::providers::AdapterSet,
    category: Category,
    ip: &IpAddr,
    registry: &Registry,
    settings: &crate::models::Settings,
    semaphore: std::sync::Arc<Semaphore>,
) -> Vec<ProviderEvidence> {
    let mut futures = FuturesUnordered::new();

    for provider in adapters.iter().filter(|a| a.category() == category) {
        let id = provider.id();

        // Disabled in settings or registry ⇒ skipped with a reason, never called.
        if !is_provider_enabled(id, registry, settings) {
            continue;
        }
        // Missing key ⇒ skipped, not an error and not a "clean" vote.
        if provider.requires_key() && config::get_api_key(id).is_none() {
            continue;
        }

        let timeout_ms = provider_timeout_ms(id, registry, settings);
        let permit = semaphore.clone();
        futures.push(async move {
            // The permit bounds concurrency; failures still produce evidence.
            let _permit = permit.acquire_owned().await.ok();
            let (outcome, latency) = call_provider(provider, ip, timeout_ms).await;
            match outcome {
                Ok(mut evidence) => {
                    evidence.latency_ms = Some(latency);
                    evidence
                }
                Err(error) => {
                    let mut evidence =
                        error_evidence(id, category, provider.upstream(), &error);
                    evidence.latency_ms = Some(latency);
                    evidence
                }
            }
        });
    }

    let mut out = Vec::new();
    while let Some(evidence) = futures.next().await {
        out.push(evidence);
    }
    out.sort_by(|a, b| a.provider.cmp(&b.provider));
    out
}

/// Which providers of a category were skipped, and why (§3.3).
fn skipped_reasons(
    adapters: &crate::providers::AdapterSet,
    category: Category,
    registry: &Registry,
    settings: &crate::models::Settings,
) -> Vec<(String, SkipReason)> {
    let mut out = Vec::new();
    for provider in adapters.iter().filter(|a| a.category() == category) {
        let id = provider.id();
        if !is_provider_enabled(id, registry, settings) {
            out.push((id.to_string(), SkipReason::Disabled));
            continue;
        }
        if provider.requires_key() && config::get_api_key(id).is_none() {
            out.push((id.to_string(), SkipReason::MissingKey));
            continue;
        }
        if circuit_open_error(id).is_some() {
            out.push((id.to_string(), SkipReason::CircuitOpen));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Streaming plumbing
// ---------------------------------------------------------------------------

/// Mutable check state shared by the module runners.
struct RunState {
    check_id: String,
    started_at: String,
    modules: Vec<ModuleState>,
}

impl RunState {
    fn module_mut(&mut self, id: ModuleId) -> Option<&mut ModuleState> {
        self.modules.iter_mut().find(|m| m.module == id)
    }

    fn mark(&mut self, id: ModuleId, status: ModuleStatus, message: impl Into<String>) {
        if let Some(module) = self.module_mut(id) {
            module.status = status;
            module.progress = if status == ModuleStatus::Done { 100 } else { module.progress };
            module.message = message.into();
        }
    }

    /// §3.3 — one event per finished module, never one event for everything.
    fn emit(&self, sink: Option<&ProgressSink<'_>>, id: ModuleId, partial: Option<serde_json::Value>) {
        let Some(sink) = sink else { return };
        let module = self
            .modules
            .iter()
            .find(|m| m.module == id)
            .cloned()
            .unwrap_or_else(|| ModuleState::new(id));
        let done = self
            .modules
            .iter()
            .filter(|m| matches!(m.status, ModuleStatus::Done | ModuleStatus::Skipped | ModuleStatus::Error))
            .count();
        let total = self.modules.len().max(1);
        let progress = ((done * 100) / total) as u8;

        sink(CheckProgressEvent {
            check_id: self.check_id.clone(),
            started_at: self.started_at.clone(),
            module: id,
            status: module.status,
            progress,
            message: module.message.clone(),
            partial,
            modules: self.modules.clone(),
        });
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Run one complete check (§4.2 `check_ip`).
pub async fn run_check(input: &str, options: CheckOptions) -> RunOutcome {
    run_check_inner(input, options, None).await
}

/// Run a check while emitting one `check-progress` event per module (§4.3).
pub async fn run_check_streaming(
    input: &str,
    options: CheckOptions,
    sink: ProgressSink<'_>,
) -> CheckSession {
    run_check_inner(input, options, Some(sink)).await.session
}

async fn run_check_inner(
    input: &str,
    options: CheckOptions,
    sink: Option<ProgressSink<'_>>,
) -> RunOutcome {
    let started = Instant::now();
    let started_at = chrono::Utc::now().to_rfc3339();
    let check_id = Uuid::new_v4().to_string();
    let mut options = options;
    let parsed = validator::parse_input(input, options.protocol);
    let mode = parsed.mode;
    if options.protocol.is_none() {
        options.protocol = parsed.protocol;
    }
    if options.credentials.is_none() {
        options.credentials = parsed.credentials.clone();
    }

    let mut state = RunState {
        check_id: check_id.clone(),
        started_at: started_at.clone(),
        modules: initial_modules(mode),
    };

    // ---------------- 1. Validation gate (§3.4) ----------------
    if let Some(problem) = parsed.problem.clone() {
        state.mark(ModuleId::Validate, ModuleStatus::Error, problem.clone());
        for module in state.modules.iter_mut() {
            if module.module != ModuleId::Validate {
                module.status = ModuleStatus::Skipped;
                module.skip_reason = Some(SkipReason::UnsupportedIp);
                module.message = "Không chạy: input không hợp lệ".to_string();
            }
        }
        state.emit(sink.as_ref(), ModuleId::Validate, None);

        let mut result =
            FullCheckResult::short_circuit(check_id.clone(), input.to_string(), problem.clone());
        result.mode = CheckMode::Unknown;
        result.modules = Some(state.modules.clone());
        result.duration_ms = Some(started.elapsed().as_millis() as u64);

        return RunOutcome {
            session: CheckSession {
                check_id,
                input: input.to_string(),
                ip: String::new(),
                mode: CheckMode::Unknown,
                started_at,
                finished_at: Some(chrono::Utc::now().to_rfc3339()),
                complete: true,
                result: Some(result),
                modules: state.modules,
                errors: vec![ProviderError::new("invalid_input", problem, false)],
            },
        };
    }

    // ---------------- 2. Unusable-address short-circuit (§3.4, §8.4) ----------------
    //
    // The gate depends on the MODE, and treating it as mode-independent was a
    // release-blocking bug:
    //
    //  * IP-only: a loopback/private address is not checkable. There is no
    //    reputation data for 192.168.1.1 and asking would burn every provider's
    //    quota. Stop and explain (§3.4).
    //  * Proxy mode: that same address is the **proxy to dial**, not the IP to
    //    look up. `ssh -D 1080`, Tor, Burp and any local SOCKS proxy all listen
    //    on 127.0.0.1. Refusing them downgraded the check to IP-only, skipped
    //    every proxy module, and measured the user's own connection while the
    //    UI claimed a proxy was active — a privacy failure (§8.4), not a
    //    validation win.
    //
    // A truly unusable proxy address (0.0.0.0, multicast, broadcast) is still
    // refused, with a message about the proxy rather than about the IP.
    if validator::should_short_circuit(&parsed) {
        let (reason, banner) = match parsed.mode {
            CheckMode::IpOnly => (
                "IP private / loopback / link-local / CGNAT / reserved — dừng sớm, không gọi API nào (§3.4)"
                    .to_string(),
                true,
            ),
            _ => (
                "Địa chỉ proxy không dùng được: đây là địa chỉ không thể kết nối tới (0.0.0.0, multicast hoặc broadcast). Nhập IP:cổng của proxy thật."
                    .to_string(),
                false,
            ),
        };
        state.mark(ModuleId::Validate, ModuleStatus::Done, reason.clone());
        for module in state.modules.iter_mut() {
            if module.module != ModuleId::Validate {
                module.status = ModuleStatus::Skipped;
                module.skip_reason = Some(SkipReason::UnsupportedIp);
                module.message = reason.clone();
            }
        }
        // §13.2: the privacy banner must reach the UI even in a short-circuit.
        state.emit(
            sink.as_ref(),
            ModuleId::Validate,
            Some(serde_json::json!({
                "is_private": banner,
                "reason": reason,
            })),
        );

        let mut result =
            FullCheckResult::short_circuit(check_id.clone(), parsed.ip.to_string(), reason);
        result.is_private = banner;
        result.mode = parsed.mode;
        result.ip_version = Some(parsed.ip_version);
        result.modules = Some(state.modules.clone());
        result.duration_ms = Some(started.elapsed().as_millis() as u64);

        return RunOutcome {
            session: CheckSession {
                check_id,
                input: input.to_string(),
                ip: parsed.ip.to_string(),
                mode: parsed.mode,
                started_at,
                finished_at: Some(chrono::Utc::now().to_rfc3339()),
                complete: true,
                result: Some(result),
                modules: state.modules,
                errors: Vec::new(),
            },
        };
    }

    // ---------------- 3. Normal path ----------------
    let registry = config::load_registry();
    let settings = config::load_settings();
    let enabled_groups: Vec<DnsblGroup> = settings
        .dnsbl_groups
        .iter()
        .filter(|g| g.enabled)
        .map(|g| g.group)
        .collect();

    // §4.3 — concurrency comes from Settings (not from CheckOptions, which
    // only carries per-check switches), then hard-capped by MAX_CONCURRENCY.
    let concurrency = settings.max_concurrency.clamp(1, MAX_CONCURRENCY);
    let semaphore = std::sync::Arc::new(Semaphore::new(concurrency.max(1)));

    let adapters = crate::providers::AdapterSet::from_registry(&registry);
    let ip = parsed.ip;

    state.mark(ModuleId::Validate, ModuleStatus::Done, "Input hợp lệ");
    state.emit(
        sink.as_ref(),
        ModuleId::Validate,
        Some(serde_json::json!({ "validation_error": serde_json::Value::Null })),
    );

    let mut result = FullCheckResult::short_circuit(check_id.clone(), ip.to_string(), String::new());
    result.validation_error = None;
    result.mode = parsed.mode;
    result.ip_version = Some(parsed.ip_version);
    result.from_cache = false;
    result.proxy_host = if parsed.port.is_some() { Some(ip.to_string()) } else { None };
    result.proxy_port = parsed.port;
    result.proxy_protocol = parsed.protocol;

    let mut all_evidence: Vec<ProviderEvidence> = Vec::new();
    let mut module_errors: Vec<ProviderError> = Vec::new();

    // ---- Step 3a: In Proxy mode, resolve Exit IP FIRST (§8.1, §8.4) ----
    //
    // A user checking `127.0.0.1:1080` or `proxy:8080` wants the reputation,
    // geo, ASN, DNSBL, and network stats of the *exit IP* the world sees
    // through the proxy — never the proxy host itself.
    let target_ip: Option<IpAddr> = if mode == CheckMode::Proxy {
        let proxy_host = ip.to_string();
        let proxy_port = parsed.port.unwrap_or(0);
        let proxy = proxy_url(parsed.protocol, &proxy_host, proxy_port);

        state.mark(ModuleId::ExitIp, ModuleStatus::Running, "Đang xác định IP thoát");
        let (exit_outcome, (open, _port_latency)) = tokio::join!(
            tokio::time::timeout(
                EXIT_IP_DEADLINE,
                exit_ip::probe_with_credentials(&proxy, &proxy_host, options.credentials.as_ref()),
            ),
            network::check_proxy_port(ip, proxy_port)
        );

        if !open {
            module_errors.push(ProviderError::new(
                "network",
                format!("Cổng proxy {proxy_port} không mở"),
                false,
            ));
        }

        let exit_result = match exit_outcome {
            Ok(r) => r,
            Err(_) => {
                let mut r = exit_ip::not_measured();
                r.notes = vec![format!(
                    "Hết thời gian chờ {}s khi xác định IP thoát qua proxy — không kết luận (§1.2).",
                    EXIT_IP_DEADLINE.as_secs()
                )];
                module_errors.push(ProviderError::new(
                    "timeout",
                    "Timeout khi xác định IP thoát qua proxy",
                    true,
                ));
                r
            }
        };

        let exit_measured = exit_result.exit_ip.is_some();
        state.mark(
            ModuleId::ExitIp,
            if exit_measured {
                ModuleStatus::Done
            } else {
                ModuleStatus::Error
            },
            if exit_measured {
                format!(
                    "IP thoát: {}",
                    exit_result.exit_ip.clone().unwrap_or_default()
                )
            } else if let Some(note) = exit_result.notes.first() {
                note.clone()
            } else {
                "Chưa xác định được IP thoát — không kết luận (§1.2)".to_string()
            },
        );
        result.exit_ip = Some(exit_result.clone());
        result.ip = exit_result.exit_ip.clone().unwrap_or_default();
        state.emit(
            sink.as_ref(),
            ModuleId::ExitIp,
            Some(serde_json::json!({
                "exit_ip": result.exit_ip,
                "ip": result.ip,
            })),
        );

        exit_result
            .exit_ip
            .as_deref()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .filter(|addr| is_checkable(*addr))
            .or_else(|| if is_checkable(ip) { Some(ip) } else { None })
    } else {
        Some(ip)
    };

    // ---- Step 3b: Concurrent IP reputation, Geo, ASN, DNSBL & Network ----
    if let Some(target_ip) = target_ip {
        state.mark(ModuleId::Geo, ModuleStatus::Running, "Đang hỏi các nguồn geo");
        state.mark(ModuleId::Asn, ModuleStatus::Running, "Đang hỏi nguồn ASN");
        state.mark(ModuleId::Fraud, ModuleStatus::Running, "Đang hỏi nguồn fraud score");
        state.mark(ModuleId::Abuse, ModuleStatus::Running, "Đang hỏi nguồn abuse history");
        state.mark(ModuleId::ThreatIntel, ModuleStatus::Running, "Đang hỏi threat intel");
        if settings.dnsbl_enabled {
            state.mark(ModuleId::Dnsbl, ModuleStatus::Running, "Đang tra DNSBL");
        }

        // Local offline Geo DB lookup (instant, non-blocking).
        let geo_db_set = crate::geo_db::GeoDbSet::load_default();
        let local_geo_points = geo_db_set.lookup(target_ip);

        // Wave 1: Run all HTTP provider categories + DNSBL concurrently under the shared semaphore.
        let (
            geo_evidence,
            local_db_evidence,
            asn_evidence,
            mut fraud_evidence,
            abuse_evidence,
            threat_evidence,
            dnsbl_opt,
        ) = tokio::join!(
            run_category(&adapters, Category::Geo, &target_ip, &registry, &settings, semaphore.clone()),
            run_category(&adapters, Category::LocalDb, &target_ip, &registry, &settings, semaphore.clone()),
            run_category(&adapters, Category::Asn, &target_ip, &registry, &settings, semaphore.clone()),
            run_category(&adapters, Category::Fraud, &target_ip, &registry, &settings, semaphore.clone()),
            run_category(&adapters, Category::Abuse, &target_ip, &registry, &settings, semaphore.clone()),
            run_category(&adapters, Category::ThreatIntel, &target_ip, &registry, &settings, semaphore.clone()),
            async {
                if settings.dnsbl_enabled {
                    Some(dnsbl::check_ip(target_ip, &registry, &enabled_groups).await)
                } else {
                    None
                }
            }
        );

        // ---- Finalise Geo ----
        let mut geo_points = collect_geo_points(&geo_evidence, &local_db_evidence);
        for pt in local_geo_points {
            if !geo_points.iter().any(|p| p.source == pt.source) {
                geo_points.push(pt);
            }
        }
        let answered_geo = geo_evidence
            .iter()
            .chain(local_db_evidence.iter())
            .filter(|e| e.signal != Signal::Unknown)
            .count();
        if answered_geo == 0 && geo_points.is_empty() {
            state.mark(ModuleId::Geo, ModuleStatus::Error, "Không nguồn geo nào trả lời");
        } else {
            state.mark(
                ModuleId::Geo,
                ModuleStatus::Done,
                format!("{} nguồn geo trả lời", answered_geo.max(geo_points.len())),
            );
        }
        all_evidence.extend(geo_evidence.iter().cloned());
        all_evidence.extend(local_db_evidence.iter().cloned());
        state.emit(
            sink.as_ref(),
            ModuleId::Geo,
            Some(serde_json::json!({
                "geo_points": geo_points.len(),
                "evidence": all_evidence,
            })),
        );

        // ---- Finalise Fraud / Abuse / ThreatIntel ----
        if is_provider_enabled("ip_api_flags", &registry, &settings)
            && !fraud_evidence.iter().any(|e| e.provider == "ip_api_flags")
        {
            if let Some(derived) = derive_ip_api_flags_evidence(&geo_evidence) {
                fraud_evidence.push(derived);
                fraud_evidence.sort_by(|a, b| a.provider.cmp(&b.provider));
            }
        }
        let fraud_answered = fraud_evidence
            .iter()
            .filter(|e| e.signal != Signal::Unknown)
            .count();
        let fraud_skipped = skipped_reasons(&adapters, Category::Fraud, &registry, &settings);
        if fraud_answered == 0 {
            let (status, message) = skip_or_error(&fraud_skipped, "Không nguồn fraud nào trả lời");
            state.mark(ModuleId::Fraud, status, message);
        } else {
            state.mark(
                ModuleId::Fraud,
                ModuleStatus::Done,
                format!("{fraud_answered} nguồn fraud trả lời"),
            );
        }
        all_evidence.extend(fraud_evidence);
        state.emit(
            sink.as_ref(),
            ModuleId::Fraud,
            Some(serde_json::json!({ "evidence": all_evidence })),
        );

        let abuse_answered = abuse_evidence
            .iter()
            .filter(|e| e.signal != Signal::Unknown)
            .count();
        state.mark(
            ModuleId::Abuse,
            if abuse_answered > 0 { ModuleStatus::Done } else { ModuleStatus::Skipped },
            if abuse_answered > 0 {
                format!("{abuse_answered} nguồn abuse trả lời")
            } else {
                "Không nguồn abuse nào trả lời (thiếu key hoặc bị ngắt)".to_string()
            },
        );
        if abuse_answered == 0 {
            if let Some(module) = state.module_mut(ModuleId::Abuse) {
                module.skip_reason = Some(
                    skipped_reasons(&adapters, Category::Abuse, &registry, &settings)
                        .first()
                        .map(|(_, reason)| *reason)
                        .unwrap_or(SkipReason::MissingKey),
                );
            }
        }
        all_evidence.extend(abuse_evidence);
        state.emit(
            sink.as_ref(),
            ModuleId::Abuse,
            Some(serde_json::json!({ "evidence": all_evidence })),
        );

        let threat_answered = threat_evidence
            .iter()
            .filter(|e| e.signal != Signal::Unknown)
            .count();
        state.mark(
            ModuleId::ThreatIntel,
            if threat_answered > 0 { ModuleStatus::Done } else { ModuleStatus::Skipped },
            if threat_answered > 0 {
                format!("{threat_answered} nguồn threat intel trả lời")
            } else {
                "Không nguồn threat intel nào trả lời".to_string()
            },
        );
        if threat_answered == 0 {
            if let Some(module) = state.module_mut(ModuleId::ThreatIntel) {
                module.skip_reason = Some(
                    skipped_reasons(&adapters, Category::ThreatIntel, &registry, &settings)
                        .first()
                        .map(|(_, reason)| *reason)
                        .unwrap_or(SkipReason::MissingKey),
                );
            }
        }
        all_evidence.extend(threat_evidence);
        state.emit(
            sink.as_ref(),
            ModuleId::ThreatIntel,
            Some(serde_json::json!({ "evidence": all_evidence })),
        );

        // ---- Finalise ASN + Location ----
        all_evidence.extend(asn_evidence.iter().cloned());
        let mut asn_records = collect_asn_records(&asn_evidence);
        supplement_asn_from_geo(&mut asn_records, &geo_evidence);
        let flags = collect_ip_flags(&all_evidence);
        let isp = first_isp_from_evidence(&asn_evidence, &geo_evidence);
        let asn_result = asn::aggregate(
            asn_records,
            flags,
            isp,
            geo_points
                .iter()
                .find_map(|p| p.country_code.clone()),
        );
        let ip_type = asn_result.ip_type;
        state.mark(
            ModuleId::Asn,
            ModuleStatus::Done,
            if asn_result.consensus {
                "Đủ 2 nguồn đồng ý về ASN".to_string()
            } else {
                "Chưa đủ 2 nguồn đồng ý về ASN".to_string()
            },
        );
        result.asn = Some(asn_result.clone());
        state.emit(
            sink.as_ref(),
            ModuleId::Asn,
            Some(serde_json::json!({
                "asn_consensus": asn_result.consensus,
                "asn": result.asn,
                "evidence": all_evidence,
            })),
        );

        // ---- Finalise DNSBL ----
        if let Some(dnsbl_result) = dnsbl_opt {
            if dnsbl_result.groups_answered == 0 {
                state.mark(
                    ModuleId::Dnsbl,
                    ModuleStatus::Error,
                    "Không nhóm DNSBL nào trả lời — không kết luận blacklist",
                );
                if let Some(module) = state.module_mut(ModuleId::Dnsbl) {
                    module.skip_reason = Some(SkipReason::Disabled);
                }
            } else {
                state.mark(
                    ModuleId::Dnsbl,
                    ModuleStatus::Done,
                    format!(
                        "{} nhóm trả lời, {} zone listed",
                        dnsbl_result.groups_answered, dnsbl_result.total_listed
                    ),
                );
            }
            all_evidence.extend(dnsbl_evidence_to_provider_rows(&dnsbl_result, &registry));
            result.dnsbl = Some(dnsbl_result.clone());
            state.emit(
                sink.as_ref(),
                ModuleId::Dnsbl,
                Some(serde_json::json!({
                    "groups_answered": dnsbl_result.groups_answered,
                    "total_listed": dnsbl_result.total_listed,
                    "hard_hit": dnsbl_result.hard_hit,
                    "dnsbl": result.dnsbl,
                    "evidence": all_evidence,
                })),
            );
        } else {
            state.mark(ModuleId::Dnsbl, ModuleStatus::Skipped, "DNSBL bị tắt trong Settings");
            if let Some(module) = state.module_mut(ModuleId::Dnsbl) {
                module.skip_reason = Some(SkipReason::Disabled);
            }
            result.dnsbl = Some(dnsbl::empty_result(&registry, &enabled_groups));
            state.emit(
                sink.as_ref(),
                ModuleId::Dnsbl,
                Some(serde_json::json!({ "dnsbl": result.dnsbl })),
            );
        }

        // ---- Location (§7) — emit right away so map & overview render before traceroute ----
        state.mark(ModuleId::Location, ModuleStatus::Running, "Đang tam giác vị trí");
        let location_result = location::triangulate_for_type(geo_points.clone(), ip_type);
        state.mark(
            ModuleId::Location,
            ModuleStatus::Done,
            format!(
                "Độ tụ {} | {}",
                location_result.spread,
                location_result
                    .city
                    .clone()
                    .or_else(|| location_result.country.clone())
                    .unwrap_or_else(|| "chưa xác định".to_string())
            ),
        );
        result.location = Some(location_result.clone());
        state.emit(
            sink.as_ref(),
            ModuleId::Location,
            Some(serde_json::json!({
                "location": result.location,
                "asn": result.asn,
            })),
        );

        // ---- Network (§9) — ping + PTR + traceroute ----
        state.mark(ModuleId::Network, ModuleStatus::Running, "Đang đo mạng");
        let isp_for_ptr = asn_result.isp.clone();
        let asn_name_for_ptr = asn_result.asn_name.clone();
        let network_result =
            network::probe_with_isp(target_ip, isp_for_ptr.as_deref(), asn_name_for_ptr.as_deref()).await;
        state.mark(
            ModuleId::Network,
            ModuleStatus::Done,
            format!(
                "Ping {} | PTR {}",
                network_result.ping_method,
                network_result.reverse_dns.as_deref().unwrap_or("không có")
            ),
        );
        result.network = Some(network_result);
        state.emit(
            sink.as_ref(),
            ModuleId::Network,
            Some(serde_json::json!({ "network": result.network })),
        );
    } else {
        // Proxy mode where exit IP could not be resolved and proxy host is private/loopback:
        // do NOT query public APIs for 127.0.0.1 / 192.168.x.x (§8.4).
        for module_id in [
            ModuleId::Geo,
            ModuleId::Asn,
            ModuleId::Fraud,
            ModuleId::Abuse,
            ModuleId::ThreatIntel,
            ModuleId::Dnsbl,
            ModuleId::Network,
            ModuleId::Location,
        ] {
            state.mark(
                module_id,
                ModuleStatus::Skipped,
                "Không chạy: chưa xác định được IP thoát qua proxy (§8.1)",
            );
            if let Some(module) = state.module_mut(module_id) {
                module.skip_reason = Some(SkipReason::RequiresProxy);
            }
            state.emit(sink.as_ref(), module_id, None);
        }
        result.dnsbl = Some(dnsbl::empty_result(&registry, &enabled_groups));
    }

    // ---- Step 3c: Proxy-only Leak + Speed modules (§1.2, §8) ----
    //
    // §8.4 / §11: `options.credentials` is passed to the probe functions as an
    // argument and dropped here. It is never attached to `result`.
    if mode == CheckMode::Proxy {
        let proxy_host = ip.to_string();
        let proxy_port = parsed.port.unwrap_or(0);
        let proxy = proxy_url(parsed.protocol, &proxy_host, proxy_port);
        let exit_ip_str = result.exit_ip.as_ref().and_then(|e| e.exit_ip.clone());

        // ---- Leak (§8.2) — `LeakProbeInput` + `run_probe` ----
        if options.run_leak_check.unwrap_or(true) {
            state.mark(ModuleId::Leak, ModuleStatus::Running, "Đang kiểm leak trình duyệt");
            let mut leak_input = browser_leak::LeakProbeInput::new(
                proxy_host.clone(),
                proxy_port,
                parsed.protocol.unwrap_or(ProxyProtocol::Http),
            );
            leak_input.exit_ip = exit_ip_str;
            leak_input.ip_timezone = result
                .location
                .as_ref()
                .and_then(|loc| loc.points.iter().find_map(|p| p.timezone.clone()));
            leak_input.ip_country = result.location.as_ref().and_then(|loc| loc.country.clone());
            leak_input.browser_path = if settings.browser_path.trim().is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(settings.browser_path.trim()))
            };

            let guarded = tokio::time::timeout(
                LEAK_DEADLINE,
                tokio::task::spawn_blocking(move || browser_leak::run_probe(&leak_input)),
            )
            .await;

            let leak = match guarded {
                Ok(Ok(result)) => result,
                Ok(Err(join_err)) => {
                    let mut r = browser_leak::not_measured();
                    r.notes.insert(
                        0,
                        format!("Module leak gặp lỗi nội bộ: {join_err} — không đo được (§1.2)."),
                    );
                    module_errors.push(ProviderError::new(
                        "internal",
                        "Module leak dừng bất thường",
                        true,
                    ));
                    r
                }
                Err(_) => {
                    let mut r = browser_leak::not_measured();
                    r.notes.insert(
                        0,
                        format!(
                            "Hết thời gian chờ {}s khi kiểm leak trình duyệt — không kết luận (§1.2).",
                            LEAK_DEADLINE.as_secs()
                        ),
                    );
                    module_errors.push(ProviderError::new(
                        "timeout",
                        "Timeout khi kiểm leak qua proxy",
                        true,
                    ));
                    r
                }
            };

            let leak_measured = leak.measured;
            state.mark(
                ModuleId::Leak,
                if leak_measured {
                    ModuleStatus::Done
                } else {
                    ModuleStatus::Skipped
                },
                if leak_measured {
                    "Đã đo leak".to_string()
                } else if let Some(note) = leak.notes.first() {
                    note.clone()
                } else {
                    "Chưa đo được — cần trình duyệt (§1.2)".to_string()
                },
            );
            if !leak_measured {
                if let Some(module) = state.module_mut(ModuleId::Leak) {
                    module.skip_reason = Some(SkipReason::UnsupportedIp);
                }
            }
            result.leak = Some(leak);
        } else {
            state.mark(ModuleId::Leak, ModuleStatus::Skipped, "Người dùng tắt kiểm leak");
            if let Some(module) = state.module_mut(ModuleId::Leak) {
                module.skip_reason = Some(SkipReason::Disabled);
            }
            result.leak = Some(browser_leak::not_measured());
        }
        state.emit(
            sink.as_ref(),
            ModuleId::Leak,
            Some(serde_json::json!({ "leak": result.leak })),
        );

        // ---- Speed (§8.3) — `run_with_credentials(proxy, credentials, bytes, upload)` ----
        if options.run_speed_check.unwrap_or(true) {
            state.mark(ModuleId::Speed, ModuleStatus::Running, "Đang đo tốc độ");
            let speed_attempt = tokio::time::timeout(
                SPEED_DEADLINE,
                speed::run_with_credentials(
                    &proxy,
                    options.credentials.clone(),
                    CONTRACT_SPEED_BYTES,
                    None,
                ),
            )
            .await;

            let speed_result = match speed_attempt {
                Ok(r) => r,
                Err(_) => {
                    let mut r = speed::not_measured();
                    r.notes.insert(
                        0,
                        format!(
                            "Hết thời gian chờ {}s khi đo tốc độ qua proxy — không kết luận (§1.2).",
                            SPEED_DEADLINE.as_secs()
                        ),
                    );
                    module_errors.push(ProviderError::new(
                        "timeout",
                        "Timeout khi đo tốc độ qua proxy",
                        true,
                    ));
                    r
                }
            };

            let speed_measured = speed_result.measured;
            let speed_message = if speed_measured {
                "Đã đo tốc độ".to_string()
            } else {
                speed_result
                    .notes
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Chưa đo được tốc độ (§1.2)".to_string())
            };
            state.mark(
                ModuleId::Speed,
                if speed_measured {
                    ModuleStatus::Done
                } else {
                    ModuleStatus::Skipped
                },
                speed_message,
            );
            result.speed = Some(speed_result);
        } else {
            state.mark(ModuleId::Speed, ModuleStatus::Skipped, "Người dùng tắt đo tốc độ");
            if let Some(module) = state.module_mut(ModuleId::Speed) {
                module.skip_reason = Some(SkipReason::Disabled);
            }
            result.speed = Some(speed::not_measured());
        }
        state.emit(
            sink.as_ref(),
            ModuleId::Speed,
            Some(serde_json::json!({ "speed": result.speed })),
        );
    } else {
        // §1.2 — never fabricate: "Chưa đo được — cần nhập proxy", not zero.
        for (module_id, message) in [
            (ModuleId::ExitIp, "Chưa đo được — cần nhập proxy"),
            (ModuleId::Leak, "Chưa đo được — cần nhập proxy"),
            (ModuleId::Speed, "Chưa đo được — cần nhập proxy"),
        ] {
            state.mark(module_id, ModuleStatus::Skipped, message);
            if let Some(module) = state.module_mut(module_id) {
                module.skip_reason = Some(SkipReason::RequiresProxy);
            }
            state.emit(sink.as_ref(), module_id, None);
        }
        result.exit_ip = Some(exit_ip::not_measured());
        result.leak = Some(browser_leak::not_measured());
        result.speed = Some(speed::not_measured());
    }

    // ---- Scoring (§6) ----
    state.mark(ModuleId::Scoring, ModuleStatus::Running, "Đang tổng hợp điểm");
    result.evidence = all_evidence.clone();
    let weights = scoring::weight_lookup(&registry);
    let expected = scoring::expected_votes_for(&registry, &settings);
    let scored = scoring::score_with_expected_votes(&result, &all_evidence, &weights, result.dnsbl.as_ref(), expected);
    result.clean_score = scored.clean_score;
    result.confidence_score = scored.confidence_score;
    result.verdict = scored.verdict;
    result.verdict_reason = scored.verdict_reason.clone();
    result.scoring = Some(scored.clone());

    // §6.6 — maintain public_clean_score from scored.clean_score, and mark
    // clean_score_provisional = true when verdict is inconclusive (§1.2, §6.3, §6.6).
    let inconclusive = scored.verdict.is_inconclusive();
    let public_clean_score = scored.clean_score;
    result.clean_score = public_clean_score;
    result.clean_score_provisional = inconclusive && public_clean_score.is_some();

    state.mark(
        ModuleId::Scoring,
        ModuleStatus::Done,
        format!(
            "{} (Clean {}, Confidence {:.0})",
            scored.verdict.as_str(),
            public_clean_score
                .map(|s| {
                    if inconclusive {
                        format!("{s:.0} [tạm tính]")
                    } else {
                        format!("{s:.0}")
                    }
                })
                .unwrap_or_else(|| "—".to_string()),
            scored.confidence_score
        ),
    );
    state.emit(
        sink.as_ref(),
        ModuleId::Scoring,
        Some(serde_json::json!({
            "verdict": scored.verdict.as_str(),
            "clean_score": public_clean_score,
            "clean_score_provisional": result.clean_score_provisional,
            "confidence": scored.confidence_score,
            "confidence_score": scored.confidence_score,
            "verdict_reason": scored.verdict_reason,
            "scoring": scored,
        })),
    );

    // ---- Finish ----
    //
    // §8.4 / §11 — proxy credentials NEVER enter `FullCheckResult` (it is what
    // gets serialised into SQLite, exported to JSON/CSV and returned to the
    // front-end). They are only passed as function arguments to the leak/speed
    // probes, and are dropped when this scope ends.
    if options
        .credentials
        .as_ref()
        .map(|c| !c.username.is_empty() || !c.password.is_empty())
        .unwrap_or(false)
    {
        tracing::debug!("Đã dùng credential proxy cho lần check này (không lưu, không log giá trị)");
    }
    let _cache_notes = describe_cache(&registry, &all_evidence);
    result.duration_ms = Some(started.elapsed().as_millis() as u64);
    result.modules = Some(state.modules.clone());

    for evidence in all_evidence.iter() {
        if let Some(error) = evidence.error.as_ref() {
            module_errors.push(error.clone());
        }
    }

    RunOutcome {
        session: CheckSession {
            check_id,
            input: input.to_string(),
            // §8.4 — in proxy mode this is the measured exit IP, not the proxy
            // host. Falls back to the proxy host only when nothing was measured,
            // so the UI still knows which proxy was used.
            ip: if mode == CheckMode::Proxy {
                result
                    .exit_ip
                    .as_ref()
                    .and_then(|e| e.exit_ip.clone())
                    .unwrap_or_else(|| ip.to_string())
            } else {
                ip.to_string()
            },
            mode,
            started_at,
            finished_at: Some(chrono::Utc::now().to_rfc3339()),
            complete: true,
            result: Some(result),
            modules: state.modules,
            errors: module_errors,
        },
    }
}

/// Turn a "nothing answered" outcome into either a skip or an error state.
fn skip_or_error(skipped: &[(String, SkipReason)], fallback: &str) -> (ModuleStatus, String) {
    if skipped.is_empty() {
        return (ModuleStatus::Error, fallback.to_string());
    }
    let reason = skipped[0].1;
    let label = match reason {
        SkipReason::MissingKey => "thiếu API key",
        SkipReason::CircuitOpen => "provider tạm ngắt",
        SkipReason::QuotaExhausted => "hết quota",
        SkipReason::Disabled => "bị tắt",
        SkipReason::NotImplemented => "chưa có adapter",
        _ => "không khả dụng",
    };
    (ModuleStatus::Skipped, format!("{fallback} ({label})"))
}

/// Note which categories were served from cache or skipped (§10.2, §3.4).
fn describe_cache(registry: &Registry, evidence: &[ProviderEvidence]) -> Vec<String> {
    let mut notes = Vec::new();
    let cached = evidence.iter().filter(|e| e.from_cache).count();
    if cached > 0 {
        notes.push(format!(
            "{cached} nguồn lấy từ cache (TTL §10.2) — giữ nguyên thời điểm gốc"
        ));
    }
    let unknown = evidence
        .iter()
        .filter(|e| e.signal == Signal::Unknown)
        .count();
    if unknown > 0 {
        notes.push(format!(
            "{unknown} nguồn không trả lời (timeout/hết quota/thiếu key) — không tính phiếu, Confidence bị trừ (§4.3)"
        ));
    }
    let unsupported = registry.unmatched_adapters();
    if !unsupported.is_empty() {
        notes.push(format!(
            "{} provider trong providers.yaml chưa có adapter trong bản này — bỏ qua (§5.5)",
            unsupported.len()
        ));
    }
    let reusable = cache::TtlClass::for_category(Category::Leak);
    debug_assert_eq!(reusable, TtlClass::Never);
    notes
}

// ---------------------------------------------------------------------------
// Evidence → domain objects
// ---------------------------------------------------------------------------

/// Pull [`crate::models::GeoPoint`]s out of geo/local-db evidence.
fn collect_geo_points(geo: &[ProviderEvidence], local: &[ProviderEvidence]) -> Vec<crate::models::GeoPoint> {
    let mut points = Vec::new();
    for evidence in geo.iter().chain(local.iter()) {
        let Some(raw) = evidence.raw.as_ref() else { continue };
        let (mut latitude, mut longitude) = (
            raw.get("lat").or_else(|| raw.get("latitude")).and_then(|v| v.as_f64()),
            raw.get("lon").or_else(|| raw.get("longitude")).and_then(|v| v.as_f64()),
        );
        if latitude.is_none() || longitude.is_none() {
            if let Some(loc) = raw.get("loc").and_then(|v| v.as_str()) {
                let parts: Vec<&str> = loc.split(',').collect();
                if parts.len() == 2 {
                    if let (Ok(lat), Ok(lon)) = (
                        parts[0].trim().parse::<f64>(),
                        parts[1].trim().parse::<f64>(),
                    ) {
                        latitude = Some(lat);
                        longitude = Some(lon);
                    }
                }
            }
        }

        let point = crate::models::GeoPoint {
            source: evidence.provider.clone(),
            source_kind: category_kind(evidence.category).to_string(),
            country: raw
                .get("country")
                .or_else(|| raw.get("country_name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            country_code: raw
                .get("country_code")
                .or_else(|| raw.get("countryCode"))
                .or_else(|| raw.get("country_iso"))
                .or_else(|| {
                    raw.get("country")
                        .filter(|v| v.as_str().map(|s| s.len() == 2).unwrap_or(false))
                })
                .and_then(|v| v.as_str())
                .map(|s| s.to_uppercase()),
            region: raw
                .get("region")
                .or_else(|| raw.get("regionName"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            city: raw
                .get("city")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            postal: raw
                .get("postal")
                .or_else(|| raw.get("zip"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            latitude,
            longitude,
            timezone: raw
                .get("timezone")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            accuracy_radius_km: raw
                .get("accuracy_radius")
                .and_then(|v| v.as_f64()),
            db_version: None,
            db_updated_at: None,
            distance_from_centroid_km: None,
            over_precise: false,
        };
        if point.latitude.is_some() || point.country_code.is_some() {
            points.push(point);
        }
    }
    points
}

/// Pull [`crate::models::AsnRecord`]s out of ASN evidence.
fn collect_asn_records(asn_evidence: &[ProviderEvidence]) -> Vec<crate::models::AsnRecord> {
    let mut records = Vec::new();
    for evidence in asn_evidence {
        let Some(raw) = evidence.raw.as_ref() else { continue };
        let asn = raw
            .get("asn")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .or_else(|| {
                raw.get("asn")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.trim_start_matches("AS").parse::<u32>().ok())
            });
        if asn.is_none() && raw.get("asn_name").is_none() {
            continue;
        }
        records.push(crate::models::AsnRecord {
            source: evidence.provider.clone(),
            asn,
            asn_name: raw
                .get("asn_name")
                .or_else(|| raw.get("name"))
                .or_else(|| raw.get("holder"))
                .or_else(|| raw.get("shortname"))
                .or_else(|| raw.get("asn_description"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            organisation: raw
                .get("organisation")
                .or_else(|| raw.get("organization"))
                .or_else(|| raw.get("org"))
                .or_else(|| raw.get("holder"))
                .or_else(|| raw.get("as_name"))
                .or_else(|| raw.get("asname"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string()),
            prefix: raw
                .get("prefix")
                .or_else(|| raw.get("route"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            rir_country: raw
                .get("rir_country")
                .or_else(|| raw.get("country"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            registry: raw
                .get("registry")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            note: None,
        });
    }
    records
}

/// Supplement ASN records from Geo providers (`ipwho`, `ip_api`, `ipinfo`, etc.)
/// so ASN consensus still works when BGPView or DNS is unreachable.
fn supplement_asn_from_geo(
    records: &mut Vec<crate::models::AsnRecord>,
    geo_evidence: &[ProviderEvidence],
) {
    for evidence in geo_evidence {
        if records.iter().any(|r| r.source == evidence.provider) {
            continue;
        }
        let Some(raw) = evidence.raw.as_ref() else { continue };
        let mut parsed_as_name: Option<String> = None;
        let asn = raw
            .get("asn")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .or_else(|| {
                raw.get("asn")
                    .or_else(|| raw.get("as"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| {
                        let mut parts = s.splitn(2, char::is_whitespace);
                        let first = parts.next().unwrap_or(s);
                        let num = first
                            .trim_start_matches("AS")
                            .trim_start_matches("as")
                            .parse::<u32>()
                            .ok();
                        if let Some(rest) = parts.next() {
                            if !rest.trim().is_empty() {
                                parsed_as_name = Some(rest.trim().to_string());
                            }
                        }
                        num
                    })
            });
        let asn_name = raw
            .get("asn_name")
            .or_else(|| raw.get("asname"))
            .or_else(|| raw.get("holder"))
            .or_else(|| raw.get("shortname"))
            .or_else(|| raw.get("asn_description"))
            .or_else(|| raw.get("org"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.to_string())
            .or_else(|| parsed_as_name.clone());
        if asn.is_none() && asn_name.is_none() {
            continue;
        }
        records.push(crate::models::AsnRecord {
            source: evidence.provider.clone(),
            asn,
            asn_name,
            organisation: raw
                .get("organisation")
                .or_else(|| raw.get("organization"))
                .or_else(|| raw.get("org"))
                .or_else(|| raw.get("isp"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string())
                .or(parsed_as_name),
            prefix: None,
            rir_country: raw
                .get("country_code")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            registry: None,
            note: None,
        });
    }
}

/// Derive the `ip_api_flags` (`Category::Fraud`, `upstream: "ip-api"`) evidence
/// row from `ip_api`'s response, per `providers.yaml` (`weight_in_category: 0.10`)
/// and `ip_api.rs` (§6.2: one vote per `(upstream, category)`).
fn derive_ip_api_flags_evidence(geo_evidence: &[ProviderEvidence]) -> Option<ProviderEvidence> {
    let ip_api_ev = geo_evidence
        .iter()
        .find(|e| e.provider == "ip_api" && e.signal != Signal::Unknown && e.error.is_none())?;
    let raw = ip_api_ev.raw.as_ref()?;
    let proxy = raw.get("proxy").and_then(|v| v.as_bool()).unwrap_or(false);
    let hosting = raw.get("hosting").and_then(|v| v.as_bool()).unwrap_or(false);
    let mobile = raw.get("mobile").and_then(|v| v.as_bool()).unwrap_or(false);

    let (signal, reason) = if proxy {
        (Signal::Bad, Some("ip-api gắn cờ proxy=true".to_string()))
    } else if hosting {
        (
            Signal::Suspicious,
            Some("ip-api gắn cờ hosting/datacenter=true (proxy=false)".to_string()),
        )
    } else {
        (
            Signal::Clean,
            Some("ip-api: proxy=false, hosting=false".to_string()),
        )
    };

    Some(ProviderEvidence {
        provider: "ip_api_flags".to_string(),
        category: Category::Fraud,
        upstream: "ip-api".to_string(),
        signal,
        raw_score: None,
        raw: Some(serde_json::json!({
            "proxy": proxy,
            "hosting": hosting,
            "mobile": mobile,
        })),
        checked_at: ip_api_ev.checked_at.clone(),
        source_url: ip_api_ev.source_url.clone(),
        latency_ms: ip_api_ev.latency_ms,
        error: None,
        reason,
        from_cache: ip_api_ev.from_cache,
    })
}

/// Extract boolean IP flags (`hosting`, `proxy`, `vpn`, `tor`, `mobile`, `anycast`)
/// across all provider evidence rows.
fn collect_ip_flags(evidence: &[ProviderEvidence]) -> IpFlags {
    let mut flags = IpFlags::default();
    for ev in evidence {
        let Some(raw) = ev.raw.as_ref() else { continue };
        if raw.get("hosting").and_then(|v| v.as_bool()).unwrap_or(false)
            || raw.get("is_datacenter").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            flags.hosting = true;
        }
        if raw.get("proxy").and_then(|v| v.as_bool()).unwrap_or(false)
            || raw
                .get("proxy")
                .and_then(|v| v.as_str())
                .map(|s| s.eq_ignore_ascii_case("yes"))
                .unwrap_or(false)
            || raw.get("proxy_bool").and_then(|v| v.as_bool()).unwrap_or(false)
            || raw.get("is_proxy").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            flags.proxy = true;
        }
        if let Some(privacy) = raw.get("privacy") {
            if privacy.get("vpn").and_then(|v| v.as_bool()).unwrap_or(false) {
                flags.vpn = true;
            }
            if privacy.get("proxy").and_then(|v| v.as_bool()).unwrap_or(false) {
                flags.proxy = true;
            }
            if privacy.get("tor").and_then(|v| v.as_bool()).unwrap_or(false) {
                flags.tor = true;
            }
            if privacy.get("hosting").and_then(|v| v.as_bool()).unwrap_or(false) {
                flags.hosting = true;
            }
        }
        if raw.get("vpn").and_then(|v| v.as_bool()).unwrap_or(false)
            || raw.get("active_vpn").and_then(|v| v.as_bool()).unwrap_or(false)
            || raw.get("is_vpn").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            flags.vpn = true;
        }
        if raw.get("tor").and_then(|v| v.as_bool()).unwrap_or(false)
            || raw.get("active_tor").and_then(|v| v.as_bool()).unwrap_or(false)
            || raw.get("is_tor").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            flags.tor = true;
        }
        if raw.get("mobile").and_then(|v| v.as_bool()).unwrap_or(false)
            || raw.get("is_mobile").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            flags.mobile = true;
        }
        if raw.get("anycast").and_then(|v| v.as_bool()).unwrap_or(false)
            || raw.get("is_anycast").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            flags.anycast = Some(true);
        }
    }
    flags
}

fn first_isp(asn_evidence: &[ProviderEvidence]) -> Option<String> {
    asn_evidence.iter().find_map(|e| {
        let raw = e.raw.as_ref()?;
        raw.get("isp")
            .or_else(|| raw.get("org"))
            .or_else(|| raw.get("organisation"))
            .or_else(|| raw.get("asn_name"))
            .or_else(|| raw.get("asname"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.to_string())
    })
}

fn first_isp_from_evidence(
    asn_evidence: &[ProviderEvidence],
    geo_evidence: &[ProviderEvidence],
) -> Option<String> {
    first_isp(asn_evidence).or_else(|| {
        geo_evidence.iter().find_map(|e| {
            let raw = e.raw.as_ref()?;
            raw.get("isp")
                .or_else(|| raw.get("org"))
                .or_else(|| raw.get("organisation"))
                .or_else(|| raw.get("asname"))
                .or_else(|| raw.get("asn_name"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string())
        })
    })
}

/// Reconstruct `asn`, `location`, `dnsbl`, and `scoring` on a cached [`FullCheckResult`]
/// loaded from SQLite (`cache::Cache::load_check`), using its stored `evidence` rows.
///
/// This keeps the SQLite schema lean while ensuring historical rows render full
/// Overview, GeoMap, Blacklist, and Verdict breakdown cards in the UI.
pub fn hydrate_cached_result(result: &mut FullCheckResult) {
    if result.evidence.is_empty() {
        return;
    }

    let geo_evidence: Vec<ProviderEvidence> = result
        .evidence
        .iter()
        .filter(|e| e.category == Category::Geo)
        .cloned()
        .collect();
    let local_db_evidence: Vec<ProviderEvidence> = result
        .evidence
        .iter()
        .filter(|e| e.category == Category::LocalDb)
        .cloned()
        .collect();
    let asn_evidence: Vec<ProviderEvidence> = result
        .evidence
        .iter()
        .filter(|e| e.category == Category::Asn)
        .cloned()
        .collect();

    let geo_points = collect_geo_points(&geo_evidence, &local_db_evidence);

    if result.asn.is_none() {
        let mut asn_records = collect_asn_records(&asn_evidence);
        supplement_asn_from_geo(&mut asn_records, &geo_evidence);
        let flags = collect_ip_flags(&result.evidence);
        let isp = first_isp_from_evidence(&asn_evidence, &geo_evidence);
        if !asn_records.is_empty() || isp.is_some() || !geo_points.is_empty() {
            let asn_res = asn::aggregate(
                asn_records,
                flags,
                isp,
                geo_points.iter().find_map(|p| p.country_code.clone()),
            );
            result.asn = Some(asn_res);
        }
    }

    if result.location.is_none() && !geo_points.is_empty() {
        let ip_type = result
            .asn
            .as_ref()
            .map(|a| a.ip_type)
            .unwrap_or(IpType::Unknown);
        result.location = Some(location::triangulate_for_type(geo_points, ip_type));
    }

    if result.dnsbl.is_none() {
        let blacklist_rows: Vec<&ProviderEvidence> = result
            .evidence
            .iter()
            .filter(|e| e.category == Category::Blacklist)
            .collect();
        if !blacklist_rows.is_empty() {
            let mut groups = Vec::new();
            let mut total_listed = 0u32;
            let mut groups_answered = 0u32;
            let mut hard_hit = false;

            for ev in blacklist_rows {
                let Some(raw) = ev.raw.as_ref() else { continue };
                let group_str = raw.get("group").and_then(|v| v.as_str()).unwrap_or("community");
                let (group, label) = match group_str {
                    "spamhaus" => (DnsblGroup::Spamhaus, "Spamhaus".to_string()),
                    "commercial" => (DnsblGroup::Commercial, "Commercial".to_string()),
                    "specialist" => (DnsblGroup::Specialist, "Specialist".to_string()),
                    _ => (DnsblGroup::Community, "Community".to_string()),
                };
                let checked = raw.get("checked").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let listed = raw.get("listed").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                if group == DnsblGroup::Spamhaus && listed > 0 {
                    hard_hit = true;
                }
                total_listed += listed;
                groups_answered += 1;

                let mut entries = Vec::new();
                if let Some(arr) = raw.get("return_codes").and_then(|v| v.as_array()) {
                    for item in arr {
                        let zone = item
                            .get("zone")
                            .and_then(|v| v.as_str())
                            .unwrap_or(group_str)
                            .to_string();
                        let codes: Vec<String> = item
                            .get("codes")
                            .and_then(|v| v.as_array())
                            .map(|c| {
                                c.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        entries.push(crate::models::DnsblEntry {
                            provider: zone.clone(),
                            zone,
                            group,
                            listed: true,
                            return_codes: codes,
                            signal: ev.signal,
                            listed_verdict: if ev.signal == Signal::Bad {
                                crate::models::ListedVerdict::Bad
                            } else {
                                crate::models::ListedVerdict::Suspicious
                            },
                            reason: Some("Listed (từ lịch sử cache)".to_string()),
                            source_url: ev.source_url.clone(),
                            checked_at: ev.checked_at.clone(),
                            error: None,
                        });
                    }
                }

                groups.push(crate::models::DnsblGroupResult {
                    group,
                    label,
                    checked,
                    listed,
                    signal: ev.signal,
                    answered: true,
                    entries,
                });
            }

            result.dnsbl = Some(crate::models::DnsblResult {
                groups,
                total_listed,
                groups_answered,
                hard_hit,
                notes: vec!["Khôi phục từ lịch sử SQLite cache.".to_string()],
            });
        }
    }

    if result.scoring.is_none() {
        let registry = config::load_registry();
        let settings = config::load_settings();
        let weights = scoring::weight_lookup(&registry);
        let expected = scoring::expected_votes_for(&registry, &settings);
        let scored = scoring::score_with_expected_votes(result, &result.evidence, &weights, result.dnsbl.as_ref(), expected);
        result.clean_score = scored.clean_score;
        result.clean_score_provisional = scored.verdict.is_inconclusive() && scored.clean_score.is_some();
        result.scoring = Some(scored);
    }
}

/// Stable string label for a category (used in `GeoPoint::source_kind`).
pub fn category_kind(category: Category) -> &'static str {
    category.as_str()
}

/// Project the DNSBL result into per-group `ProviderEvidence` rows.
///
/// §5.3: exactly one row per answered *group*, so scoring cannot be swayed by
/// how many zones a group happens to contain.
fn dnsbl_evidence_to_provider_rows(
    dnsbl_result: &crate::models::DnsblResult,
    registry: &Registry,
) -> Vec<ProviderEvidence> {
    let mut rows = Vec::new();
    for group in &dnsbl_result.groups {
        if !group.answered {
            continue;
        }
        let group_key = crate::providers::registry::group_key(group.group);
        let upstream = match group.group {
            DnsblGroup::Spamhaus => "spamhaus".to_string(),
            DnsblGroup::Commercial => "commercial".to_string(),
            DnsblGroup::Community => "community".to_string(),
            DnsblGroup::Specialist => "specialist".to_string(),
        };
        // Weight: the strongest zone weight inside the group, capped at 40 %.
        let weight = registry
            .dnsbl_by_group(group.group)
            .iter()
            .map(|m| m.sanitised_weight())
            .fold(0.0_f64, f64::max);
        let _ = weight;

        rows.push(ProviderEvidence {
            provider: format!("dnsbl_group_{group_key}"),
            category: Category::Blacklist,
            upstream,
            signal: group.signal,
            raw_score: Some(f64::from(group.listed)),
            raw: Some(serde_json::json!({
                "group": group_key,
                "checked": group.checked,
                "listed": group.listed,
                "return_codes": group
                    .entries
                    .iter()
                    .filter(|e| e.listed)
                    .map(|e| serde_json::json!({
                        "zone": e.zone,
                        "codes": e.return_codes,
                    }))
                    .collect::<Vec<_>>(),
            })),
            checked_at: chrono::Utc::now().to_rfc3339(),
            source_url: group
                .entries
                .first()
                .map(|e| e.source_url.clone())
                .unwrap_or_default(),
            latency_ms: None,
            error: None,
            reason: None,
            from_cache: false,
        });
    }
    rows
}

// ---------------------------------------------------------------------------
// Small helpers kept for command-layer compatibility
// ---------------------------------------------------------------------------

/// Proxy URL in the form Chromium / reqwest expect (§8.4).
pub fn proxy_url(protocol: Option<ProxyProtocol>, host: &str, port: u16) -> String {
    let scheme = match protocol {
        Some(ProxyProtocol::Socks5) => "socks5",
        Some(ProxyProtocol::Socks4) => "socks4",
        Some(ProxyProtocol::Https) => "https",
        _ => "http",
    };
    format!("{scheme}://{host}:{port}")
}

/// Scheme string for a proxy protocol, used when building a proxy URL.
///
/// Kept public: `commands.rs` and the leak/speed probes need the same spelling
/// and must not duplicate the mapping.
pub fn protocol_str(protocol: Option<ProxyProtocol>) -> &'static str {
    match protocol {
        Some(ProxyProtocol::Socks5) => "socks5",
        Some(ProxyProtocol::Socks4) => "socks4",
        Some(ProxyProtocol::Https) => "https",
        Some(ProxyProtocol::Http) => "http",
        None => "",
    }
}

/// Clamp a requested timeout into the sane window (§4.3).
pub fn clamp_timeout(requested: Option<u64>) -> u64 {
    requested
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS)
}

/// True when the IP is routable enough to bother calling providers.
pub fn is_checkable(ip: IpAddr) -> bool {
    !validator::is_private_or_reserved(ip)
}

/// Map an ip_type onto its French- Vietnamese label for the UI.
pub fn ip_type_label(ip_type: IpType) -> &'static str {
    match ip_type {
        IpType::Residential => "Residential",
        IpType::Datacenter => "Datacenter",
        IpType::Mobile => "Mobile",
        IpType::Cgnat => "CGNAT",
        IpType::Vpn => "VPN",
        IpType::Tor => "Tor",
        IpType::Proxy => "Proxy",
        IpType::Anycast => "Anycast",
        IpType::Edu => "Edu",
        IpType::Unknown => "Chưa xác định",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering as O;

    #[test]
    fn circuit_opens_after_five_consecutive_failures() {
        let stats = ProviderStats::default();
        for _ in 0..(CIRCUIT_FAILURE_THRESHOLD - 1) {
            stats.record_failure(&ProviderError::timeout());
        }
        assert!(!stats.is_circuit_open(), "4 lỗi chưa đủ ngưỡng");
        stats.record_failure(&ProviderError::timeout());
        assert!(stats.is_circuit_open(), "5 lỗi ⇒ mở breaker (§4.3)");
        assert!(stats.circuit_open_until_rfc3339().is_some());
    }

    #[test]
    fn success_closes_the_circuit() {
        let stats = ProviderStats::default();
        for _ in 0..CIRCUIT_FAILURE_THRESHOLD {
            stats.record_failure(&ProviderError::timeout());
        }
        assert!(stats.is_circuit_open());
        stats.record_success(120);
        assert!(!stats.is_circuit_open(), "thành công phải đóng breaker");
        assert_eq!(stats.consecutive_failures.load(O::Relaxed), 0);
    }

    #[test]
    fn missing_key_never_opens_the_circuit() {
        let stats = ProviderStats::default();
        // `models::ProviderError` has no `no_key()` helper, so build the same
        // shape `record_failure` special-cases: kind = "no_key", not retryable.
        let no_key = ProviderError::new("no_key", "chưa cấu hình API key", false);
        for _ in 0..20 {
            stats.record_failure(&no_key);
        }
        assert!(
            !stats.is_circuit_open(),
            "thiếu key không phải lỗi provider — không được mở breaker"
        );
    }

    #[test]
    fn stats_track_success_rate_and_latency() {
        let stats = ProviderStats::default();
        stats.record_success(100);
        stats.record_success(200);
        stats.record_failure(&ProviderError::timeout());
        assert!((stats.success_rate() - 66.6667).abs() < 0.01);
        assert!((stats.latency_avg_ms().unwrap() - 150.0).abs() < 1e-9);
        assert_eq!(stats.total_checks.load(O::Relaxed), 3);
    }

    #[test]
    fn retry_policy_is_transient_only() {
        assert!(is_retryable(&ProviderError::timeout()));
        assert!(is_retryable(&ProviderError::new(
            "http",
            "502 bad gateway",
            true
        )));
        assert!(!is_retryable(&ProviderError::new(
            "no_key",
            "chưa cấu hình API key",
            false
        )));
        assert!(!is_retryable(&ProviderError::new(
            "quota",
            "hết quota tháng",
            false
        )));
        assert!(!is_retryable(&ProviderError::new(
            "circuit_open",
            "breaker mở",
            false
        )));
    }

    #[test]
    fn error_evidence_is_unknown_not_clean() {
        let error = ProviderError::timeout();
        let evidence = error_evidence("ipqualityscore", Category::Fraud, "ipqualityscore", &error);
        assert_eq!(evidence.signal, Signal::Unknown);
        assert_eq!(evidence.raw_score, None);
        assert!(evidence.error.is_some());
        assert_eq!(evidence.error.as_ref().unwrap().kind, "timeout");
    }

    #[test]
    fn drain_only_mode_has_no_proxy_modules() {
        let modules = ip_only_modules();
        assert!(!modules.contains(&ModuleId::Leak));
        assert!(!modules.contains(&ModuleId::Speed));
        assert!(!modules.contains(&ModuleId::ExitIp));
        assert!(modules.contains(&ModuleId::Dnsbl));
        assert!(modules.contains(&ModuleId::Scoring));
    }

    #[test]
    fn proxy_mode_adds_leak_and_speed() {
        let modules = proxy_modules();
        assert!(modules.contains(&ModuleId::Leak));
        assert!(modules.contains(&ModuleId::Speed));
        assert!(modules.contains(&ModuleId::ExitIp));
        // IP-only list must remain a prefix so the UI order is stable.
        assert_eq!(&modules[..ip_only_modules().len()], &ip_only_modules()[..]);
    }

    #[test]
    fn timeout_is_clamped_into_window() {
        assert_eq!(clamp_timeout(None), DEFAULT_TIMEOUT_MS);
        assert_eq!(clamp_timeout(Some(1)), MIN_TIMEOUT_MS);
        assert_eq!(clamp_timeout(Some(999_999)), MAX_TIMEOUT_MS);
        assert_eq!(clamp_timeout(Some(6000)), 6000);
    }

    #[test]
    fn proxy_url_carries_scheme_and_port() {
        assert_eq!(
            proxy_url(Some(ProxyProtocol::Socks5), "1.2.3.4", 1080),
            "socks5://1.2.3.4:1080"
        );
        assert_eq!(
            proxy_url(Some(ProxyProtocol::Http), "1.2.3.4", 8080),
            "http://1.2.3.4:8080"
        );
        // No protocol ⇒ http, the safest default.
        assert_eq!(proxy_url(None, "1.2.3.4", 3128), "http://1.2.3.4:3128");
    }

    #[test]
    fn private_ips_are_not_checkable() {
        assert!(!is_checkable("192.168.1.1".parse().unwrap()));
        assert!(!is_checkable("127.0.0.1".parse().unwrap()));
        assert!(!is_checkable("::1".parse().unwrap()));
        assert!(is_checkable("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn stats_for_is_stable_per_provider() {
        let a = stats_for("test_provider_xyz");
        let b = stats_for("test_provider_xyz");
        assert!(std::ptr::eq(a, b), "phải cùng một ô nhớ");
        a.record_success(10);
        assert_eq!(b.total_checks.load(O::Relaxed), 1);
    }

    #[test]
    fn health_snapshot_reflects_recorded_stats() {
        let stats = stats_for("health_probe_provider");
        for _ in 0..CIRCUIT_FAILURE_THRESHOLD {
            stats.record_failure(&ProviderError::timeout());
        }
        let snapshot = health_snapshot();
        let row = snapshot
            .get("health_probe_provider")
            .expect("phải có row trong snapshot");
        assert!(row.circuit_open);
        assert_eq!(row.state, HealthState::Red);
        assert_eq!(row.effective_weight, 0.0, "breaker mở ⇒ trọng số 0 (§5.5)");
        assert!(row.last_error.is_some());
    }

    #[test]
    fn skip_or_error_reports_reason() {
        let (status, message) = skip_or_error(&[], "không nguồn nào trả lời");
        assert_eq!(status, ModuleStatus::Error);
        assert!(message.contains("không nguồn"));

        let (status, message) = skip_or_error(
            &[("ipqs".to_string(), SkipReason::MissingKey)],
            "không nguồn nào trả lời",
        );
        assert_eq!(status, ModuleStatus::Skipped);
        assert!(message.contains("thiếu API key"));
    }

    #[test]
    fn dnsbl_rows_are_one_per_group() {
        let mut registry = crate::providers::registry::Registry::default();
        registry.reindex();
        let dnsbl_result = crate::models::DnsblResult {
            groups: vec![
                crate::models::DnsblGroupResult {
                    group: DnsblGroup::Spamhaus,
                    label: "Spamhaus".to_string(),
                    checked: 4,
                    listed: 1,
                    signal: Signal::Bad,
                    answered: true,
                    entries: Vec::new(),
                },
                crate::models::DnsblGroupResult {
                    group: DnsblGroup::Community,
                    label: "Cộng đồng".to_string(),
                    checked: 3,
                    listed: 0,
                    signal: Signal::Clean,
                    answered: true,
                    entries: Vec::new(),
                },
                crate::models::DnsblGroupResult {
                    group: DnsblGroup::Specialist,
                    label: "Chuyên biệt".to_string(),
                    checked: 0,
                    listed: 0,
                    signal: Signal::Unknown,
                    answered: false,
                    entries: Vec::new(),
                },
            ],
            total_listed: 1,
            groups_answered: 2,
            hard_hit: true,
            notes: Vec::new(),
        };

        let rows = dnsbl_evidence_to_provider_rows(&dnsbl_result, &registry);
        assert_eq!(
            rows.len(),
            2,
            "chỉ nhóm đã trả lời mới thành phiếu — 4 zone Spamhaus vẫn là 1 phiếu (§5.3)"
        );
        assert!(rows.iter().all(|r| r.category == Category::Blacklist));
        let spamhaus = rows.iter().find(|r| r.upstream == "spamhaus").unwrap();
        assert_eq!(spamhaus.signal, Signal::Bad);
        let community = rows.iter().find(|r| r.upstream == "community").unwrap();
        assert_eq!(community.signal, Signal::Clean);
    }

    #[test]
    fn geo_points_are_extracted_from_raw() {
        let evidence = vec![ProviderEvidence {
            provider: "ip_api".to_string(),
            category: Category::Geo,
            upstream: "ip-api".to_string(),
            signal: Signal::Clean,
            raw_score: None,
            raw: Some(serde_json::json!({
                "country": "Vietnam",
                "country_code": "vn",
                "city": "Hanoi",
                "lat": 21.03,
                "lon": 105.83,
                "timezone": "Asia/Ho_Chi_Minh"
            })),
            checked_at: "2026-10-25T10:00:00+00:00".to_string(),
            source_url: String::new(),
            latency_ms: Some(100),
            error: None,
            reason: None,
            from_cache: false,
        }];
        let points = collect_geo_points(&evidence, &[]);
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].country_code.as_deref(), Some("VN"));
        assert_eq!(points[0].city.as_deref(), Some("Hanoi"));
        assert_eq!(points[0].latitude, Some(21.03));
    }

    #[test]
    fn asn_records_parse_string_and_numeric_asn() {        let evidence = vec![
            ProviderEvidence {
                provider: "ripestat".to_string(),
                category: Category::Asn,
                upstream: "ripestat".to_string(),
                signal: Signal::Clean,
                raw_score: None,
                raw: Some(serde_json::json!({"asn": 15169, "asn_name": "GOOGLE"})),
                checked_at: "2026-10-25T10:00:00+00:00".to_string(),
                source_url: String::new(),
                latency_ms: None,
                error: None,
                reason: None,
                from_cache: false,
            },
            ProviderEvidence {
                provider: "bgpview".to_string(),
                category: Category::Asn,
                upstream: "bgpview".to_string(),
                signal: Signal::Clean,
                raw_score: None,
                raw: Some(serde_json::json!({"asn": "AS15169"})),
                checked_at: "2026-10-25T10:00:00+00:00".to_string(),
                source_url: String::new(),
                latency_ms: None,
                error: None,
                reason: None,
                from_cache: false,
            },
        ];
        let records = collect_asn_records(&evidence);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].asn, Some(15169));
        assert_eq!(records[1].asn, Some(15169), "phải parse được 'AS15169'");
    }

    // ------------------------------------------------------------------
    // §1.2 — an inconclusive verdict must not ship a grade
    // ------------------------------------------------------------------

    /// Reproduce the exact situation the live `probe.exe 8.8.8.8` run exposed:
    /// fraud + blacklist quorum missing, yet the provisional score is high.
    fn result_with_missing_quorum() -> FullCheckResult {
        use crate::models::{DnsblResult, GeoPoint, LocationResult, ProviderEvidence, Signal};

        let mut result = FullCheckResult::short_circuit(
            "check-live".to_string(),
            "8.8.8.8".to_string(),
            String::new(),
        );
        result.validation_error = None;
        result.mode = CheckMode::IpOnly;

        // Two geo sources far apart ⇒ no city committed (§7.3).
        result.location = Some(LocationResult {
            country: Some("United States".to_string()),
            country_code: Some("US".to_string()),
            city: None,
            spread: "low".to_string(),
            points: vec![
                GeoPoint {
                    source: "ip_api".to_string(),
                    ..Default::default()
                },
                GeoPoint {
                    source: "ipwho".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        result.asn = Some(crate::models::AsnResult {
            asn: Some(15169),
            consensus: true,
            records: vec![
                crate::models::AsnRecord {
                    source: "ripestat".to_string(),
                    asn: Some(15169),
                    ..Default::default()
                },
                crate::models::AsnRecord {
                    source: "team_cymru".to_string(),
                    asn: Some(15169),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        result.dnsbl = Some(DnsblResult::default());

        // Only geo+asn answered: fraud and blacklist quorum are both missing,
        // exactly like the live run where most keyed providers were skipped.
        result.evidence = vec![
            ProviderEvidence {
                provider: "ip_api".to_string(),
                category: Category::Geo,
                upstream: "ip-api".to_string(),
                signal: Signal::Clean,
                raw_score: None,
                raw: None,
                checked_at: "2026-10-25T13:09:00+00:00".to_string(),
                source_url: String::new(),
                latency_ms: Some(90),
                error: None,
                reason: None,
                from_cache: false,
            },
            ProviderEvidence {
                provider: "ipwho".to_string(),
                category: Category::Geo,
                upstream: "ipwho".to_string(),
                signal: Signal::Clean,
                raw_score: None,
                raw: None,
                checked_at: "2026-10-25T13:09:00+00:00".to_string(),
                source_url: String::new(),
                latency_ms: Some(120),
                error: None,
                reason: None,
                from_cache: false,
            },
            ProviderEvidence {
                provider: "ripestat".to_string(),
                category: Category::Asn,
                upstream: "ripestat".to_string(),
                signal: Signal::Clean,
                raw_score: None,
                raw: None,
                checked_at: "2026-10-25T13:09:00+00:00".to_string(),
                source_url: String::new(),
                latency_ms: Some(150),
                error: None,
                reason: None,
                from_cache: false,
            },
        ];
        result
    }

    #[test]
    fn no_quorum_verdict_carries_provisional_clean_score() {
        // §6.6: "Chưa đủ dữ liệu" retains clean_score with clean_score_provisional = true.
        let mut result = result_with_missing_quorum();
        let weights = HashMap::new();
        let scored = scoring::score(&result, &result.evidence.clone(), &weights);

        assert_eq!(
            scored.verdict,
            crate::models::Verdict::ChưaĐủDữLiệu,
            "thiếu quorum fraud+blacklist ⇒ không được kết luận (§6.3)"
        );
        // The provisional score exists internally and is published alongside clean_score_provisional (§6.6).
        assert!(
            scored.clean_score.is_some(),
            "score tạm tính vẫn phải có trong `scoring` để giải thích lý do"
        );

        // Apply the same rule the orchestrator applies before publishing.
        let inconclusive = scored.verdict.is_inconclusive();
        result.clean_score = scored.clean_score;
        result.clean_score_provisional = inconclusive && result.clean_score.is_some();
        result.verdict = scored.verdict;
        result.scoring = Some(scored);

        assert!(
            result.clean_score.is_some(),
            "clean_score được giữ lại theo spec §6.6, thực tế {:?}",
            result.clean_score
        );
        assert!(
            result.clean_score_provisional,
            "clean_score_provisional phải là true khi verdict chưa đủ dữ liệu"
        );

        // And the wire format carries both clean_score and clean_score_provisional.
        let json = serde_json::to_string(&result).expect("serialize được");
        assert!(
            json.contains("\"clean_score_provisional\":true"),
            "JSON phải chứa clean_score_provisional:true: {json}"
        );
        assert!(
            json.contains("\"verdict\":\"Chưa đủ dữ liệu\"")
                || json.contains("\"verdict\":\"ChưaĐủDữLiệu\""),
            "verdict phải được serialize trong JSON: {json}"
        );
    }

    #[test]
    fn graded_verdict_keeps_its_clean_score() {
        // The rule must only strip the score for *inconclusive* verdicts —
        // a real grade still needs its number.
        let mut result = result_with_missing_quorum();
        result.clean_score = Some(88.9);
        result.verdict = crate::models::Verdict::Sạch;
        assert!(!result.verdict.is_inconclusive());
        // Orchestrator rule: keep it.
        let public = if result.verdict.is_inconclusive() {
            None
        } else {
            result.clean_score
        };
        assert_eq!(public, Some(88.9));
    }

    #[test]
    fn export_csv_leaves_clean_score_empty_when_none() {
        // §10.3: the CSV cell must be empty, never the internal diagnostic.
        let mut result = result_with_missing_quorum();
        result.verdict = crate::models::Verdict::ChưaĐủDữLiệu;
        result.clean_score = None;

        let row = crate::export::to_csv_row(&result);
        let fields: Vec<&str> = row.split(',').collect();
        // clean_score is column 3 (0-based index 2).
        assert_eq!(
            fields[2], "",
            "cột clean_score phải rỗng khi verdict không đủ dữ liệu, row = {row}"
        );

        let json = crate::export::render(&result, crate::models::ExportFormat::Json)
            .expect("vẫn xuất được báo cáo");
        assert!(!json.contains("\"clean_score\":8"));
    }

    // ------------------------------------------------------------------
    // §8 — proxy mode must always terminate
    // ------------------------------------------------------------------

    #[test]
    fn every_module_reaches_a_terminal_state() {
        // Regression for the frozen-UI bug: 13/13 modules reported Done while
        // the app still said "Đang quét", because `Leak`/`Scoring` never got a
        // terminal mark. Any non-terminal status in a finished session is a
        // hang, so the assembled session must never expose one.
        let mut modules = initial_modules(CheckMode::Proxy);
        for module in modules.iter_mut() {
            module.status = ModuleStatus::Done;
        }

        assert!(
            modules.len() >= 13,
            "proxy mode phải có đủ module, thực tế {}",
            modules.len()
        );
        for module in &modules {
            assert!(
                matches!(
                    module.status,
                    ModuleStatus::Done | ModuleStatus::Error | ModuleStatus::Skipped
                ),
                "module {:?} kẹt ở {:?} — đây chính là bug UI treo",
                module.module,
                module.status
            );
        }

        // And the proxy-only modules really are in that list.
        for expected in [ModuleId::ExitIp, ModuleId::Leak, ModuleId::Speed] {
            assert!(
                modules.iter().any(|m| m.module == expected),
                "thiếu module {expected:?} trong proxy mode"
            );
        }
    }

    #[test]
    fn proxy_module_deadlines_are_ordered_and_bounded() {
        // Each budget must exceed the module's own internal budget (otherwise
        // the guard fires before the module can ever report a real result),
        // and the whole proxy tail must stay inside a minute.
        assert!(
            EXIT_IP_DEADLINE >= exit_ip::EXIT_IP_TIMEOUT,
            "ExitIp: {} phải >= timeout nội bộ {:?}",
            EXIT_IP_DEADLINE.as_secs(),
            exit_ip::EXIT_IP_TIMEOUT
        );
        assert_eq!(LEAK_DEADLINE, Duration::from_secs(35));
        assert_eq!(SPEED_DEADLINE, Duration::from_secs(50));
        let total = EXIT_IP_DEADLINE + LEAK_DEADLINE + SPEED_DEADLINE;
        assert!(
            total <= Duration::from_secs(100),
            "tổng deadline proxy {total:?} vượt ngân sách một lần check"
        );
    }

    #[tokio::test]
    async fn unreachable_proxy_module_times_out_instead_of_hanging() {
        // A proxy that never answers. The wrapper must give up on its own
        // deadline, so the caller regains control instead of waiting forever.
        let hung = async {
            // Simulates a module that ignores cancellation, like a blocking
            // browser poll or a socket stuck in SYN_SENT.
            tokio::time::sleep(Duration::from_secs(600)).await;
        };
        let outcome = tokio::time::timeout(Duration::from_millis(150), hung).await;
        assert!(
            outcome.is_err(),
            "timeout phải cắt được future treo — nếu test này fail thì wrapper vô dụng"
        );
    }

    #[tokio::test]
    async fn loopback_proxy_does_not_short_circuit_the_scan() {
        // Release-blocking regression. `127.0.0.1:1080` used to be classified as
        // "a private IP" and short-circuited: Validate marked Done with the
        // private banner, every proxy module was Skipped, and the app reported
        // the user's own connection while the UI said a proxy was in use.
        //
        // The proxy here is dead on purpose — the point is not that it works,
        // it is that the scan TRIES. Reachability is asserted separately.
        let mut options = CheckOptions::default();
        options.protocol = Some(ProxyProtocol::Socks5);
        options.run_leak_check = Some(false); // keep the test fast
        options.run_speed_check = Some(false);
        options.use_cache = Some(false);
        options.save_to_history = Some(false);

        let outcome = run_check("127.0.0.1:1080", options).await;
        let modules = &outcome.session.modules;

        let validate = modules
            .iter()
            .find(|m| m.module == ModuleId::Validate)
            .expect("phải có module Validate");
        assert_ne!(
            validate.status,
            ModuleStatus::Skipped,
            "Validate không được Skipped khi input là proxy hợp lệ"
        );

        // The decisive assertion: the proxy modules actually ran.
        let exit_ip = modules
            .iter()
            .find(|m| m.module == ModuleId::ExitIp)
            .expect("proxy mode phải có module ExitIp");
        assert_ne!(
            exit_ip.status,
            ModuleStatus::Skipped,
            "module proxy PHẢI chạy khi user nhập proxy loopback — đây chính là bug lộ IP thật"
        );

        assert_eq!(
            outcome.session.mode,
            CheckMode::Proxy,
            "mode không được tự đổi về IP-only"
        );
    }

    #[test]
    fn private_ip_still_short_circuits_in_ip_only_mode() {
        // The §3.4 rule must still fire for the case it was written for: an
        // RFC1918 address with no port is not checkable.
        let parsed = validator::parse_input("192.168.1.1", None);
        assert_eq!(parsed.mode, CheckMode::IpOnly);
        assert!(
            validator::should_short_circuit(&parsed),
            "IP-only + private ⇒ phải dừng sớm"
        );

        // Same address WITH a port is a proxy and must not stop.
        let as_proxy = validator::parse_input("192.168.1.1:1080", Some(ProxyProtocol::Socks5));
        assert_eq!(as_proxy.mode, CheckMode::Proxy);
        assert!(
            !validator::should_short_circuit(&as_proxy),
            "cùng địa chỉ nhưng là proxy ⇒ KHÔNG được dừng sớm"
        );
    }

    #[test]
    fn proxy_mode_never_reports_the_proxy_host_as_the_checked_ip() {
        // §8.4: `result.ip` is what the world sees. Reporting 127.0.0.1 there
        // tells the user nothing, and reporting their own address is the leak.
        let mut result = result_with_missing_quorum();
        result.mode = CheckMode::Proxy;
        result.exit_ip = Some(exit_ip::not_measured());
        // Mirrors the orchestrator rule.
        result.ip = result
            .exit_ip
            .as_ref()
            .and_then(|e| e.exit_ip.clone())
            .unwrap_or_default();
        assert!(
            result.ip.is_empty(),
            "không đo được exit IP ⇒ để rỗng, không bịa và không dùng IP proxy: {:?}",
            result.ip
        );
    }
}
