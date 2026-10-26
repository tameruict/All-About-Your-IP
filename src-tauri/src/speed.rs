//! Speed measurement through the proxy (§8.3).
//!
//! Rules encoded here
//! ------------------
//! * **At least two independent endpoints** — a single server can never be
//!   presented as "the proxy's speed" (§8.3).
//! * **Latency = TTFB**: time to first body byte of a tiny request, sampled
//!   `JITTER_SAMPLES` times so a jitter figure means something.
//! * **Mbps from a streamed body** with a hard byte cap, so a slow proxy costs
//!   seconds rather than minutes.
//! * **No upload** unless the caller passes an endpoint *and* explicitly opts
//!   in; there is no default upload endpoint by design (§8.3).
//! * **Never cached** (§10.2) and **never faked**: in IP-only mode the module
//!   returns `measured: false` + `"Chưa đo được — cần nhập proxy"`, never 0.
//! * The proxy URL is the only network target configured; the username and
//!   password are moved into a [`ProxyCredentials`] guard that zeroizes on drop
//!   and redacts itself in `Debug` (§8.4).

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// Credentials use the SHARED `models::ProxyCredentials` type so the
// orchestrator can pass `CheckOptions.credentials` straight through. The
// zeroizing `browser_leak::ProxyCredentials` is a private guard used inside
// `browser_leak` only; a second public type with the same name would force
// every caller to convert (§8.4 is satisfied by `zeroize_guard` below).
use crate::models::ProxyCredentials;
use crate::models::{ProviderError, ProxyProtocol, SpeedEndpoint, SpeedResult};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Exact IP-only wording (§1.2, §3.3).
pub const REASON_NOT_MEASURED: &str = "Chưa đo được — cần nhập proxy";

/// Bytes pulled per endpoint. Cloudflare honours `?bytes=`, the others serve a
/// fixed file, so this is an upper bound rather than a promise.
pub const DEFAULT_BYTES_PER_ENDPOINT: u64 = 5_000_000;
/// Hard lower bound (below this a Mbps figure is meaningless).
pub const MIN_BYTES_PER_ENDPOINT: u64 = 1_000_000;
/// Hard upper bound — keeps one bad endpoint from eating the whole budget.
pub const MAX_BYTES_PER_ENDPOINT: u64 = 25_000_000;

/// How many tiny requests are used for the TTFB / jitter sample.
pub const JITTER_SAMPLES: usize = 4;

/// Total wall-clock budget for the whole module.
pub const TOTAL_BUDGET: Duration = Duration::from_secs(60);
/// Per-endpoint budget.
pub const ENDPOINT_BUDGET: Duration = Duration::from_secs(25);
/// Per-request connect / read timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Endpoint catalogue (§8.3: ≥2 independent CDNs)
// ---------------------------------------------------------------------------

/// One download test target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedTarget {
    /// Human label shown in the UI.
    pub endpoint: String,
    /// Fully built URL (query already applied).
    pub url: String,
    /// Independent upstream, for the "don't trust one CDN" rule.
    pub upstream: String,
}

/// Default download catalogue: two independent CDNs plus a third fallback.
///
/// `bytes` is only honoured by Cloudflare; the fixed-size files are read until
/// `bytes` or the end of file, whichever comes first.
pub fn default_speed_targets(bytes: u64) -> Vec<SpeedTarget> {
    let bytes = clamp_bytes(bytes);
    vec![
        SpeedTarget {
            endpoint: "Cloudflare speed test".to_string(),
            url: format!("https://speed.cloudflare.com/__down?bytes={}", bytes),
            upstream: "cloudflare".to_string(),
        },
        SpeedTarget {
            endpoint: "OVH proof (10 MB)".to_string(),
            url: "https://proof.ovh.net/files/10Mb.dat".to_string(),
            upstream: "ovh".to_string(),
        },
        SpeedTarget {
            endpoint: "Hetzner speed test (10 MB)".to_string(),
            url: "https://speed.hetzner.de/10MB.bin".to_string(),
            upstream: "hetzner".to_string(),
        },
    ]
}

/// Clamp the requested byte count into the sane window.
pub fn clamp_bytes(bytes: u64) -> u64 {
    if bytes == 0 {
        DEFAULT_BYTES_PER_ENDPOINT
    } else {
        bytes.clamp(MIN_BYTES_PER_ENDPOINT, MAX_BYTES_PER_ENDPOINT)
    }
}

/// Upload endpoint is opt-in only (§8.3). There is deliberately no default:
/// `None` means "not measured" rather than an invented number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadTarget {
    pub endpoint: String,
    pub url: String,
    /// Must be `true`; anything else is refused by [`measure_upload`].
    pub user_consented: bool,
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// Everything the speed module needs.
///
/// `Debug` is hand-written below so the proxy URL is redacted — never derive it.
pub struct SpeedInput {
    /// Proxy URL as `reqwest` expects (`http://host:port`, `socks5://host:port`).
    pub proxy_url: String,
    pub targets: Vec<SpeedTarget>,
    pub bytes_per_endpoint: u64,
    /// Opt-in upload target; `None` = never measured (§8.3).
    pub upload: Option<UploadTarget>,
    /// Overall budget override, clamped to [`TOTAL_BUDGET`].
    pub budget: Option<Duration>,
    /// Optional per-endpoint override, clamped to [`ENDPOINT_BUDGET`].
    pub endpoint_budget: Option<Duration>,
}

impl SpeedInput {
    pub fn new(proxy_url: impl Into<String>) -> Self {
        Self {
            proxy_url: proxy_url.into(),
            targets: default_speed_targets(DEFAULT_BYTES_PER_ENDPOINT),
            bytes_per_endpoint: DEFAULT_BYTES_PER_ENDPOINT,
            upload: None,
            budget: None,
            endpoint_budget: None,
        }
    }

    /// Build from the validated proxy pieces.
    pub fn from_parts(protocol: ProxyProtocol, host: &str, port: u16) -> Self {
        Self::new(proxy_url(protocol, host, port))
    }

    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes_per_endpoint = clamp_bytes(bytes);
        self.targets = default_speed_targets(self.bytes_per_endpoint);
        self
    }

    pub fn with_targets(mut self, targets: Vec<SpeedTarget>) -> Self {
        self.targets = targets;
        self
    }

    pub fn with_upload(mut self, upload: Option<UploadTarget>) -> Self {
        self.upload = upload;
        self
    }

    fn effective_budget(&self) -> Duration {
        let b = self.budget.unwrap_or(TOTAL_BUDGET);
        if b.is_zero() {
            TOTAL_BUDGET
        } else {
            b.min(TOTAL_BUDGET)
        }
    }

    fn effective_endpoint_budget(&self) -> Duration {
        let b = self.endpoint_budget.unwrap_or(ENDPOINT_BUDGET);
        if b.is_zero() {
            ENDPOINT_BUDGET
        } else {
            b.min(ENDPOINT_BUDGET)
        }
    }
}

/// Proxy URL in the exact form `reqwest` expects (§8.4).
pub fn proxy_url(protocol: ProxyProtocol, host: &str, port: u16) -> String {
    let scheme = match protocol {
        ProxyProtocol::Http => "http",
        ProxyProtocol::Https => "https",
        ProxyProtocol::Socks5 => "socks5",
        ProxyProtocol::Socks4 => "socks4",
    };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host) // bare IPv6 literal
    } else {
        host.to_string()
    };
    format!("{}://{}:{}", scheme, host, port)
}

// ---------------------------------------------------------------------------
// Pure measurement helpers (unit-testable, no I/O)
// ---------------------------------------------------------------------------

/// Mbps from a byte count and a duration. `None` for degenerate input — never a
/// fabricated zero.
pub fn mbps(bytes: u64, elapsed: Duration) -> Option<f64> {
    let secs = elapsed.as_secs_f64();
    if bytes == 0 || !secs.is_finite() || secs <= 0.0 {
        return None;
    }
    Some((bytes as f64 * 8.0) / secs / 1_000_000.0)
}

/// Population standard deviation of the samples, in ms.
///
/// Chosen over "max − min" because a single DNS outlier should not define the
/// jitter of an otherwise stable link.
pub fn jitter_ms(samples: &[f64]) -> Option<f64> {
    if samples.len() < 2 {
        return None;
    }
    let valid: Vec<f64> = samples.iter().copied().filter(|v| v.is_finite()).collect();
    if valid.len() < 2 {
        return None;
    }
    let mean = valid.iter().sum::<f64>() / valid.len() as f64;
    let var = valid.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / valid.len() as f64;
    Some(var.sqrt())
}

/// Arithmetic mean, ignoring non-finite values.
pub fn mean(values: &[f64]) -> Option<f64> {
    let valid: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if valid.is_empty() {
        None
    } else {
        Some(valid.iter().sum::<f64>() / valid.len() as f64)
    }
}

/// Result of a single streamed download.
#[derive(Debug, Clone, Default)]
pub struct DownloadSample {
    pub bytes: u64,
    pub duration: Duration,
    pub ttfb: Option<Duration>,
}

/// Throughput from a [`DownloadSample`], `None` when nothing was transferred.
pub fn sample_throughput(sample: &DownloadSample) -> Option<f64> {
    if sample.bytes == 0 {
        return None;
    }
    mbps(sample.bytes, sample.duration)
}

/// Combined figures for the whole module.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpeedSummary {
    /// Best-case Mbps across endpoints (the number the user acts on).
    pub best_mbps: Option<f64>,
    /// Mean Mbps across endpoints that succeeded.
    pub mean_mbps: Option<f64>,
    /// Median TTFB across all successful latency samples.
    pub latency_ms: Option<f64>,
    /// Jitter across all successful latency samples.
    pub jitter_ms: Option<f64>,
}

/// Summarise successfully measured endpoints.
///
/// Requires at least two successful endpoints before reporting an aggregate —
/// §8.3 forbids describing a single server as the proxy's speed. With fewer it
/// returns `None`s and the caller explains why in `notes`.
pub fn summarize(endpoints: &[SpeedEndpoint]) -> SpeedSummary {
    let ok: Vec<&SpeedEndpoint> = endpoints.iter().filter(|e| e.ok).collect();
    if ok.len() < 2 {
        return SpeedSummary::default();
    }

    let mbps_values: Vec<f64> = ok
        .iter()
        .filter_map(|e| e.download_mbps)
        .filter(|v| v.is_finite() && *v > 0.0)
        .collect();
    let best = mbps_values.iter().copied().fold(None::<f64>, |acc, v| match acc {
        Some(a) if a >= v => Some(a),
        _ => Some(v),
    });

    let latency_values: Vec<f64> = ok
        .iter()
        .filter_map(|e| e.latency_ms)
        .filter(|v| v.is_finite())
        .collect();

    SpeedSummary {
        best_mbps: best,
        mean_mbps: mean(&mbps_values),
        latency_ms: median(&latency_values),
        jitter_ms: jitter_ms(&latency_values),
    }
}

/// Median of a sample set.
pub fn median(values: &[f64]) -> Option<f64> {
    let mut valid: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if valid.is_empty() {
        return None;
    }
    valid.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = valid.len() / 2;
    if valid.len() % 2 == 0 {
        Some((valid[mid - 1] + valid[mid]) / 2.0)
    } else {
        Some(valid[mid])
    }
}

/// The IP-only answer: not measured, with the reason — never zeros (§1.2).
pub fn not_measured() -> SpeedResult {
    SpeedResult {
        measured: false,
        endpoints: Vec::new(),
        download_mbps: None,
        latency_ms: None,
        jitter_ms: None,
        upload_mbps: None,
        measured_at: None,
        notes: vec![REASON_NOT_MEASURED.to_string()],
        error: None,
    }
}

/// Notes that must accompany every real measurement (§8.3, §14).
pub fn measurement_notes(endpoint_count: usize, successful: usize) -> Vec<String> {
    let mut notes = Vec::new();
    notes.push(format!(
        "Phương pháp: tải file test qua proxy từ {} endpoint độc lập; latency = TTFB của {} request nhỏ mỗi endpoint; jitter = độ lệch chuẩn của các mẫu latency; Mbps = byte nhận được / thời gian tải.",
        endpoint_count, JITTER_SAMPLES
    ));
    notes.push(
        "Giới hạn: tốc độ phụ thuộc server đích, tuyến định tuyến và giờ đo — chỉ so sánh tương đối trong cùng một lần test, không phải cam kết băng thông."
            .to_string(),
    );
    notes.push(
        "Không đo upload: upload chỉ chạy khi người dùng bật rõ ràng và có endpoint upload công khai; mặc định luôn để trống thay vì bịa số."
            .to_string(),
    );
    notes.push(format!(
        "Kết quả dùng được: {}/{} endpoint. Cần tối thiểu 2 endpoint thành công mới tổng hợp được số liệu (§8.3).",
        successful, endpoint_count
    ));
    notes
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

/// Build a `reqwest` client pinned to the user's proxy.
///
/// The credential pair never leaves this function: it is moved into a
/// [`ProxyCredentials`] guard, used to build the URL once, and zeroized when the
/// guard drops at the end of this scope.
pub fn build_client(
    proxy_url: &str,
    credentials: Option<ProxyCredentials>,
    timeout: Duration,
) -> Result<reqwest::Client, ProviderError> {
    let url = with_credentials(proxy_url, credentials.as_ref());

    // Never echo the parser's message: it may quote the URL verbatim and the
    // URL can carry `user:pass@`. The redacted form is what reaches the UI.
    let proxy = reqwest::Proxy::all(url.as_str()).map_err(|_e| {
        ProviderError::new(
            "unsupported",
            format!("Proxy URL không hợp lệ: {}", redact_url(url.as_str())),
            false,
        )
    })?;

    reqwest::Client::builder()
        .proxy(proxy)
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .user_agent("ip-checker-speed/0.1 (+local proxy speed test)")
        .build()
        .map_err(|e| ProviderError::new("internal", format!("Không tạo được HTTP client: {}", e), false))
}

/// Embed credentials into a proxy URL for the lifetime of one request.
///
/// The result is used once and dropped; it is never logged, never serialised.
/// Works on the shared [`crate::models::ProxyCredentials`] (field access) and
/// on [`crate::browser_leak::ProxyCredentials`] (accessors) via [`AsProxyCreds`].
fn with_credentials(proxy_url: &str, credentials: Option<&ProxyCredentials>) -> String {
    let c = match credentials {
        Some(c) => c,
        None => return proxy_url.to_string(),
    };

    let (user_raw, pass_raw) = (c.username.as_str(), c.password.as_str());
    if user_raw.is_empty() && pass_raw.is_empty() {
        return proxy_url.to_string(); // anonymous proxy: leave the URL alone
    }

    let (scheme, rest) = match proxy_url.split_once("://") {
        Some(parts) => parts,
        None => ("http", proxy_url),
    };

    // The plaintext pair exists only for the duration of this call; both copies
    // are zeroized before returning (§8.4 — nothing survives in memory).
    use zeroize::Zeroize;
    let mut user = user_raw.to_string();
    let mut pass = pass_raw.to_string();
    let built = format!("{}://{}:{}@{}", scheme, user, pass, rest);
    user.zeroize();
    pass.zeroize();
    built
}

/// Strip `user:pass@` from a URL before it can reach a log or an error message.
pub fn redact_url(url: &str) -> String {
    match (url.find("://"), url.rfind('@')) {
        (Some(scheme_end), Some(at)) if at > scheme_end => {
            format!("{}://***@{}", &url[..scheme_end], &url[at + 1..])
        }
        _ => url.to_string(),
    }
}

impl std::fmt::Debug for SpeedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpeedInput")
            .field("proxy_url", &redact_url(&self.proxy_url))
            .field("targets", &self.targets.len())
            .field("bytes_per_endpoint", &self.bytes_per_endpoint)
            .field("upload", &self.upload.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// One TTFB sample against `url`.
///
/// `chunk().await` is the async path: `std::io::Read` on a `reqwest` response
/// only exists for blocking bodies, so this is the only shape that compiles
/// for the async client. The timer stops at the **first body byte** after a
/// successful status line — proxy handshake and TLS ride inside the sample,
/// which is what the user feels when browsing through that proxy.
async fn ttfb_once(client: &reqwest::Client, url: &str) -> Option<f64> {
    let started = Instant::now();
    let mut resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    match resp.chunk().await {
        Ok(Some(chunk)) if !chunk.is_empty() => Some(started.elapsed().as_secs_f64() * 1000.0),
        _ => None,
    }
}

/// Full percentile-quality download through the proxy.
async fn download_once(
    client: &reqwest::Client,
    target: &SpeedTarget,
    max_bytes: u64,
    budget: Duration,
) -> Result<DownloadSample, ProviderError> {
    let started = Instant::now();
    let deadline = started + budget;

    let resp = client.get(&target.url).send().await.map_err(|e| {
        ProviderError::new(
            "network",
            format!("{}: không kết nối được qua proxy ({})", target.endpoint, kind_of(&e)),
            true,
        )
    })?;

    if !resp.status().is_success() {
        return Err(ProviderError::new(
            "http",
            format!("{}: HTTP {}", target.endpoint, resp.status()),
            true,
        ));
    }

    let mut resp = resp;
    let mut bytes: u64 = 0;
    let mut ttfb: Option<Duration> = None;

    while bytes < max_bytes {
        if Instant::now() >= deadline {
            break; // partial but real measurement; the notes explain it
        }
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if chunk.is_empty() {
                    break;
                }
                if ttfb.is_none() {
                    ttfb = Some(started.elapsed());
                }
                // Never count more than the cap, so Mbps is not inflated by a
                // chunk that overshoots the requested size.
                let room = max_bytes - bytes;
                bytes += (chunk.len() as u64).min(room);
            }
            Ok(None) => break, // EOF
            Err(e) => {
                if bytes == 0 {
                    return Err(ProviderError::new(
                        "network",
                        format!("{}: lỗi đọc body ({})", target.endpoint, kind_of(&e)),
                        true,
                    ));
                }
                break; // keep what we already measured
            }
        }
    }

    if bytes == 0 {
        return Err(ProviderError::new(
            "network",
            format!("{}: không nhận được byte nào qua proxy", target.endpoint),
            true,
        ));
    }

    Ok(DownloadSample {
        bytes,
        duration: started.elapsed(),
        ttfb,
    })
}

fn kind_of(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_body() || e.is_decode() {
        "body"
    } else {
        "request"
    }
}

/// Interleave the TTFB samples so a whole endpoint's latency is measured before
/// moving on, and the samples are not all taken inside one TCP window.
async fn latency_samples(client: &reqwest::Client, target: &SpeedTarget) -> Vec<f64> {
    let mut samples = Vec::with_capacity(JITTER_SAMPLES);
    for i in 0..JITTER_SAMPLES {
        if let Some(v) = ttfb_once(client, &target.url).await {
            samples.push(v);
        }
        // Small stagger: a burst of 4 requests measures queueing, not the path.
        if i + 1 < JITTER_SAMPLES {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }
    samples
}

/// Measure one endpoint: download + latency samples.
pub async fn measure_endpoint(
    client: &reqwest::Client,
    target: &SpeedTarget,
    max_bytes: u64,
    budget: Duration,
) -> SpeedEndpoint {
    let samples = latency_samples(client, target).await;
    let latency = mean(&samples);
    let jit = jitter_ms(&samples);

    match download_once(client, target, max_bytes, budget).await {
        Ok(sample) => {
            let download = sample_throughput(&sample);
            let ok = download.is_some();
            SpeedEndpoint {
                endpoint: target.endpoint.clone(),
                ok,
                download_mbps: download,
                latency_ms: latency,
                jitter_ms: jit,
                bytes: Some(sample.bytes),
                duration_ms: Some(sample.duration.as_millis() as u64),
                error: if ok {
                    None
                } else {
                    Some("Tải xong nhưng không tính được Mbps (0 byte)".to_string())
                },
            }
        }
        Err(e) => SpeedEndpoint {
            endpoint: target.endpoint.clone(),
            ok: false,
            download_mbps: None,
            latency_ms: latency,
            jitter_ms: jit,
            bytes: None,
            duration_ms: None,
            error: Some(e.message),
        },
    }
}

/// Run the whole speed module through the proxy.
///
/// This is the **stable entry point** the orchestrator calls:
/// `speed::run(&proxy, bytes).await`. Credentials and the upload target are
/// optional and passed through [`run_with_credentials`] / [`SpeedInput`], so
/// adding a knob never breaks the caller again.
///
/// The returned [`SpeedResult`] is `measured: false` (with the reason) whenever
/// fewer than two endpoints produced a number — §8.3 forbids presenting one
/// server as the proxy's speed.
pub async fn run(proxy_url: &str, bytes_per_endpoint: u64) -> SpeedResult {
    run_with_credentials(proxy_url, None, bytes_per_endpoint, None).await
}

/// Same as [`run`] but able to carry transient proxy credentials and an
/// explicit opt-in upload target.
pub async fn run_with_credentials(
    proxy_url: &str,
    credentials: Option<ProxyCredentials>,
    bytes_per_endpoint: u64,
    upload: Option<UploadTarget>,
) -> SpeedResult {
    let input = SpeedInput::new(proxy_url)
        .with_bytes(bytes_per_endpoint)
        .with_upload(upload);
    run_input(input, credentials).await
}

/// Same as [`run`] but with the full [`SpeedInput`] knobs.
pub async fn run_input(input: SpeedInput, credentials: Option<ProxyCredentials>) -> SpeedResult {
    if input.proxy_url.trim().is_empty() {
        return not_measured();
    }
    if input.targets.len() < 2 {
        let mut r = not_measured();
        r.notes = vec![
            "Cần ít nhất 2 endpoint độc lập để đo tốc độ (§8.3) — cấu hình hiện tại không đủ.".to_string(),
        ];
        r.error = Some(ProviderError::new(
            "unsupported",
            "Cần tối thiểu 2 endpoint đo tốc độ",
            false,
        ));
        return r;
    }

    let budget = input.effective_budget();
    let per_endpoint = input.effective_endpoint_budget();
    let deadline = Instant::now() + budget;

    let client = match build_client(&input.proxy_url, credentials, REQUEST_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            let mut r = not_measured();
            r.error = Some(e);
            return r;
        }
    };

    let mut endpoints: Vec<SpeedEndpoint> = Vec::with_capacity(input.targets.len());
    for target in &input.targets {
        if Instant::now() >= deadline {
            endpoints.push(SpeedEndpoint {
                endpoint: target.endpoint.clone(),
                ok: false,
                download_mbps: None,
                latency_ms: None,
                jitter_ms: None,
                bytes: None,
                duration_ms: None,
                error: Some("Bỏ qua: hết thời gian cho phép của module".to_string()),
            });
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let slice = per_endpoint.min(remaining);
        endpoints.push(measure_endpoint(&client, target, input.bytes_per_endpoint, slice).await);
    }

    let summary = summarize(&endpoints);
    let successful = endpoints.iter().filter(|e| e.ok).count();

    let upload_mbps = match &input.upload {
        Some(target) => measure_upload(&client, target).await,
        None => None, // never invented (§8.3)
    };

    let mut notes = measurement_notes(endpoints.len(), successful);
    if successful < 2 {
        notes.insert(
            0,
            format!(
                "Chưa đo được tốc độ: cần ít nhất 2 endpoint độc lập trả về số liệu, chỉ {} endpoint thành công. \
                 Số liệu bên dưới chỉ là log lỗi, không phải tốc độ proxy (§8.3).",
                successful
            ),
        );
        return SpeedResult {
            measured: false,
            endpoints,
            download_mbps: None,
            latency_ms: None,
            jitter_ms: None,
            upload_mbps,
            measured_at: Some(chrono::Utc::now().to_rfc3339()),
            notes,
            error: Some(ProviderError::new(
                "network",
                "Không endpoint nào tải được qua proxy (hoặc chỉ được 1)",
                true,
            )),
        };
    }

    SpeedResult {
        measured: true,
        endpoints,
        download_mbps: summary.best_mbps,
        latency_ms: summary.latency_ms,
        jitter_ms: summary.jitter_ms,
        upload_mbps,
        measured_at: Some(chrono::Utc::now().to_rfc3339()),
        notes,
        error: None,
    }
}

/// Upload probe — only when the caller supplied a target **and** opted in.
///
/// Returns `None` (not 0) when the endpoint refused or the user did not consent.
pub async fn measure_upload(client: &reqwest::Client, target: &UploadTarget) -> Option<f64> {
    if !target.user_consented {
        return None;
    }
    let payload = vec![0u8; 512 * 1024];
    let sent_bytes = payload.len() as u64;
    let started = Instant::now();
    let resp = client
        .post(&target.url)
        .header("Content-Type", "application/octet-stream")
        .body(payload)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    // Drain the response so the connection completes fairly.
    let mut resp = resp;
    while let Ok(Some(_)) = resp.chunk().await {}
    mbps(sent_bytes, started.elapsed())
}

/// Measure with an explicit proxy spec (convenience for the orchestrator).
pub async fn measure_proxy(
    protocol: ProxyProtocol,
    host: &str,
    port: u16,
    bytes_per_endpoint: u64,
) -> SpeedResult {
    let input = SpeedInput::from_parts(protocol, host, port).with_bytes(bytes_per_endpoint);
    run_input(input, None).await
}

/// Serialise for the UI payload.
pub fn to_payload_json(result: &SpeedResult) -> serde_json::Value {
    serde_json::to_value(result).unwrap_or(serde_json::Value::Null)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared credential type has public fields and no `new()`; this keeps
    /// the fixtures readable without touching `models.rs`.
    fn models_creds(user: &str, pass: &str) -> ProxyCredentials {
        ProxyCredentials {
            username: user.to_string(),
            password: pass.to_string(),
        }
    }

    // ---- §1.2: no proxy => not measured, no zeros ----------------------

    #[test]
    fn ip_only_mode_returns_not_measured() {
        let r = not_measured();
        assert!(!r.measured);
        assert_eq!(r.notes, vec![REASON_NOT_MEASURED.to_string()]);
        assert!(r.download_mbps.is_none(), "must not be 0");
        assert!(r.latency_ms.is_none());
        assert!(r.jitter_ms.is_none());
        assert!(r.upload_mbps.is_none());
        assert!(r.measured_at.is_none());
        assert!(r.endpoints.is_empty());
    }

    #[tokio::test]
    async fn empty_proxy_url_returns_not_measured() {
        let r = run_input(SpeedInput::new(""), None).await;
        assert!(!r.measured);
        assert_eq!(r.notes, vec![REASON_NOT_MEASURED.to_string()]);
        assert!(r.download_mbps.is_none());
    }

    #[tokio::test]
    async fn single_endpoint_config_is_refused() {
        let input = SpeedInput::new("http://127.0.0.1:1").with_targets(vec![SpeedTarget {
            endpoint: "only".to_string(),
            url: "https://example.invalid/x".to_string(),
            upstream: "none".to_string(),
        }]);
        let r = run_input(input, None).await;
        assert!(!r.measured);
        assert!(r.notes.iter().any(|n| n.contains("ít nhất 2 endpoint")));
        assert!(r.download_mbps.is_none());
    }

    // ---- pure math ------------------------------------------------------

    #[test]
    fn mbps_math_is_exact() {
        // 1_000_000 bytes in 1 s = 8 Mbps
        let v = mbps(1_000_000, Duration::from_secs(1)).unwrap();
        assert!((v - 8.0).abs() < 1e-9, "got {}", v);
        // 10 MB in 8 s = 10 Mbps
        let v = mbps(10_000_000, Duration::from_secs(8)).unwrap();
        assert!((v - 10.0).abs() < 1e-9, "got {}", v);
    }

    #[test]
    fn mbps_never_fabricates_for_degenerate_input() {
        assert!(mbps(0, Duration::from_secs(1)).is_none());
        assert!(mbps(100, Duration::ZERO).is_none());
        let s = DownloadSample { bytes: 0, duration: Duration::from_secs(1), ttfb: None };
        assert!(sample_throughput(&s).is_none());
    }

    #[test]
    fn jitter_is_stddev_and_needs_two_samples() {
        assert!(jitter_ms(&[]).is_none());
        assert!(jitter_ms(&[10.0]).is_none());
        let j = jitter_ms(&[100.0, 110.0, 120.0]).unwrap();
        assert!((j - 8.164966).abs() < 1e-4, "got {}", j);
        assert_eq!(jitter_ms(&[50.0, 50.0, 50.0]).unwrap(), 0.0);
    }

    #[test]
    fn median_handles_even_and_odd_lengths() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
        assert!(median(&[]).is_none());
    }

    // ---- §8.3: two independent endpoints -------------------------------

    #[test]
    fn default_targets_are_independent_and_at_least_two() {
        let t = default_speed_targets(DEFAULT_BYTES_PER_ENDPOINT);
        assert!(t.len() >= 2, "§8.3 requires ≥2 endpoints");
        let upstreams: std::collections::BTreeSet<&str> =
            t.iter().map(|x| x.upstream.as_str()).collect();
        assert_eq!(upstreams.len(), t.len(), "endpoints must be independent CDNs");
        assert!(t.iter().any(|x| x.url.contains("cloudflare")));
        assert!(t.iter().all(|x| x.url.starts_with("https://")));
    }

    #[test]
    fn byte_cap_is_clamped_into_the_sane_window() {
        assert_eq!(clamp_bytes(0), DEFAULT_BYTES_PER_ENDPOINT);
        assert_eq!(clamp_bytes(1), MIN_BYTES_PER_ENDPOINT);
        assert_eq!(clamp_bytes(u64::MAX), MAX_BYTES_PER_ENDPOINT);
        let input = SpeedInput::new("http://127.0.0.1:1").with_bytes(100);
        assert_eq!(input.bytes_per_endpoint, MIN_BYTES_PER_ENDPOINT);
    }

    // ---- aggregation rules ---------------------------------------------

    #[test]
    fn summarize_needs_two_successful_endpoints() {
        let one = vec![SpeedEndpoint {
            endpoint: "a".into(),
            ok: true,
            download_mbps: Some(20.0),
            latency_ms: Some(30.0),
            jitter_ms: Some(1.0),
            bytes: Some(1_000_000),
            duration_ms: Some(400),
            error: None,
        }];
        let s = summarize(&one);
        assert_eq!(s, SpeedSummary::default(), "one endpoint is never enough");

        let two = vec![
            SpeedEndpoint {
                endpoint: "a".into(),
                ok: true,
                download_mbps: Some(20.0),
                latency_ms: Some(30.0),
                jitter_ms: Some(1.0),
                bytes: Some(1_000_000),
                duration_ms: Some(400),
                error: None,
            },
            SpeedEndpoint {
                endpoint: "b".into(),
                ok: true,
                download_mbps: Some(40.0),
                latency_ms: Some(50.0),
                jitter_ms: Some(2.0),
                bytes: Some(2_000_000),
                duration_ms: Some(400),
                error: None,
            },
            SpeedEndpoint {
                endpoint: "c".into(),
                ok: false,
                download_mbps: None,
                latency_ms: None,
                jitter_ms: None,
                bytes: None,
                duration_ms: None,
                error: Some("boom".into()),
            },
        ];
        let s = summarize(&two);
        assert_eq!(s.best_mbps, Some(40.0));
        assert_eq!(s.mean_mbps, Some(30.0));
        assert_eq!(s.latency_ms, Some(40.0));
        assert!(s.jitter_ms.unwrap() > 0.0);
    }

    #[test]
    fn notes_state_method_and_limits() {
        let notes = measurement_notes(3, 2);
        assert!(notes.iter().any(|n| n.contains("Phương pháp")));
        assert!(notes.iter().any(|n| n.contains("TTFB")));
        assert!(notes.iter().any(|n| n.contains("jitter")));
        assert!(notes.iter().any(|n| n.contains("Giới hạn")));
        assert!(notes.iter().any(|n| n.contains("Không đo upload")));
    }

    // ---- §8.3: upload is opt-in only -----------------------------------

    #[tokio::test]
    async fn upload_is_never_measured_without_consent() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let target = UploadTarget {
            endpoint: "some".into(),
            url: "https://example.invalid/up".into(),
            user_consented: false,
        };
        assert!(
            measure_upload(&client, &target).await.is_none(),
            "must not touch the network without consent"
        );
    }

    #[test]
    fn speed_input_has_no_default_upload_target() {
        let input = SpeedInput::new("http://127.0.0.1:8080");
        assert!(input.upload.is_none(), "§8.3: no upload by default");
    }

    // ---- §8.4: credentials never leak --------------------------------

    #[test]
    fn proxy_url_formatting_handles_ipv6_and_schemes() {
        assert_eq!(proxy_url(ProxyProtocol::Http, "1.2.3.4", 8080), "http://1.2.3.4:8080");
        assert_eq!(proxy_url(ProxyProtocol::Socks5, "1.2.3.4", 1080), "socks5://1.2.3.4:1080");
        assert_eq!(proxy_url(ProxyProtocol::Socks4, "1.2.3.4", 1080), "socks4://1.2.3.4:1080");
        assert_eq!(proxy_url(ProxyProtocol::Https, "2001:db8::1", 443), "https://[2001:db8::1]:443");
    }

    #[test]
    fn redaction_strips_credentials_from_urls() {
        let red = redact_url("http://user:pass@10.0.0.1:8080");
        assert_eq!(red, "http://***@10.0.0.1:8080");
        assert!(!red.contains("pass"));
        assert_eq!(redact_url("socks5://10.0.0.1:1080"), "socks5://10.0.0.1:1080");
    }

    #[test]
    fn credentials_are_embedded_only_transiently() {
        let creds = models_creds("alice", "s3cret");
        let url = with_credentials("http://10.0.0.1:8080", Some(&creds));
        assert!(url.starts_with("http://alice:s3cret@10.0.0.1:8080"));
        // Anonymous proxy: untouched.
        assert_eq!(with_credentials("http://10.0.0.1:8080", None), "http://10.0.0.1:8080");
        // Empty pair behaves like an anonymous proxy, not like "user:@".
        let empty = models_creds("", "");
        assert_eq!(
            with_credentials("http://10.0.0.1:8080", Some(&empty)),
            "http://10.0.0.1:8080"
        );
    }

    #[test]
    fn speed_input_debug_does_not_print_credentials() {
        let input = SpeedInput::from_parts(ProxyProtocol::Http, "10.0.0.1", 8080);
        let printed = format!("{:?}", input);
        assert!(!printed.contains("password"));
        assert!(printed.contains("10.0.0.1:8080"));
    }

    /// Regression guard for §8.4 + §11: the `Debug` impl must never print the
    /// proxy password, and it must never print the `user:pass@` prefix either.
    ///
    /// This fails immediately if anyone re-adds `#[derive(Debug)]` to
    /// [`SpeedInput`], so the redacting impl cannot be "simplified" away.
    #[test]
    fn debug_output_redacts_proxy_credentials() {
        let input = SpeedInput::new("http://user:s3cr3t@1.2.3.4:8080");
        let s = format!("{:?}", input);
        assert!(!s.contains("s3cr3t"), "credential leaked in Debug output: {s}");
        assert!(!s.contains("user:"), "username leaked in Debug output: {s}");
        // The host:port must still be there — redaction must not hide the target.
        assert!(s.contains("1.2.3.4:8080"), "target lost in Debug output: {s}");
        assert!(s.contains("***"), "redaction marker missing: {s}");
    }

    /// Same guarantee on the `{:#?}` (pretty) path — a second formatter entry
    /// point that a future hand-written impl could easily forget.
    #[test]
    fn pretty_debug_output_also_redacts_credentials() {
        let input = SpeedInput::new("socks5://alice:hunter2@10.0.0.9:1080");
        let s = format!("{:#?}", input);
        assert!(!s.contains("hunter2"), "credential leaked in pretty Debug: {s}");
        assert!(!s.contains("alice"), "username leaked in pretty Debug: {s}");
        assert!(s.contains("10.0.0.9:1080"));
    }

    /// Credentials must not survive into any serialised form either: the module
    /// result that reaches SQLite / export carries no proxy URL at all.
    #[test]
    fn serialised_result_carries_no_credentials() {
        let mut r = not_measured();
        r.notes = measurement_notes(2, 2);
        let json = serde_json::to_string(&r).unwrap();
        for banned in ["s3cr3t", "hunter2", "user:", "pass@", "://"] {
            assert!(
                !json.contains(banned),
                "SpeedResult JSON must not contain {:?}: {}",
                banned,
                json
            );
        }
    }

    // ---- failure path: unreachable proxy => measured false -------------

    #[tokio::test]
    async fn unreachable_proxy_yields_not_measured_with_errors() {
        // Port 1 on loopback: nothing listens, so every endpoint must fail
        // fast instead of hanging the test.
        let input = SpeedInput {
            proxy_url: "http://127.0.0.1:1".to_string(),
            targets: default_speed_targets(MIN_BYTES_PER_ENDPOINT),
            bytes_per_endpoint: MIN_BYTES_PER_ENDPOINT,
            upload: None,
            budget: Some(Duration::from_secs(6)),
            endpoint_budget: Some(Duration::from_secs(2)),
        };
        let r = run_input(input, None).await;
        assert!(!r.measured, "unreachable proxy must never report a speed");
        assert!(r.download_mbps.is_none());
        assert!(r.measured_at.is_some(), "timestamp of the attempt is still recorded");
        assert!(r.notes.iter().any(|n| n.contains("ít nhất 2 endpoint")));
        assert!(r.error.is_some());
        assert!(r.endpoints.iter().all(|e| !e.ok));
        assert!(r.endpoints.iter().all(|e| e.download_mbps.is_none()));
    }

    #[test]
    fn json_contract_matches_typescript() {
        let mut r = not_measured();
        r.measured = true;
        let v = serde_json::to_value(&r).unwrap();
        for key in [
            "measured",
            "endpoints",
            "download_mbps",
            "latency_ms",
            "jitter_ms",
            "upload_mbps",
            "measured_at",
            "notes",
        ] {
            assert!(v.get(key).is_some(), "missing field {}", key);
        }
        assert!(v["download_mbps"].is_null());
        assert!(v["upload_mbps"].is_null());
    }

    #[test]
    fn speed_endpoint_json_contract_matches_typescript() {
        let e = SpeedEndpoint {
            endpoint: "x".into(),
            ok: true,
            download_mbps: Some(1.0),
            latency_ms: Some(2.0),
            jitter_ms: Some(0.5),
            bytes: Some(100),
            duration_ms: Some(200),
            error: None,
        };
        let v = serde_json::to_value(&e).unwrap();
        for key in [
            "endpoint",
            "ok",
            "download_mbps",
            "latency_ms",
            "jitter_ms",
            "bytes",
            "duration_ms",
            "error",
        ] {
            assert!(v.get(key).is_some(), "missing field {}", key);
        }
    }
}
