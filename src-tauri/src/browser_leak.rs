//! Browser leak module — Chromium headless through the user's proxy (§8.2, §8.4).
//!
//! What this module does
//! ---------------------
//! 1. Starts a **loopback collector**: a tiny HTTP server bound to
//!    `127.0.0.1:0` (ephemeral port) that serves the bundled
//!    `ip-checker/leak-page/index.html` and accepts exactly one JSON report.
//! 2. Launches the machine's own Chromium (Edge / Chrome / Chromium /
//!    Brave, auto-detected or overridden in Settings) *headless* with
//!    `--proxy-server=<scheme>://<host>:<port>` and opens
//!    `http://127.0.0.1:<port>/?token=<nonce>`.
//! 3. The page collects WebRTC ICE candidates, `/dns-probe` reachability,
//!    timezone / language and automation fingerprints, then POSTs one JSON
//!    blob back to the collector.
//! 4. The blob is turned into a [`LeakResult`] whose `notes` spell out the
//!    **method** and the **limits** — never an absolute claim.
//!
//! Hard rules encoded here
//! -----------------------
//! * §8.4 — only the proxy the user typed is contacted. No default credential
//!   is ever tried. [`ProxyCredentials`] keeps username/password in
//!   `Zeroizing` strings, redacts them in `Debug`, and is never serialised.
//! * §8.4 — the browser gets a hard 20–30 s budget; the child is killed and
//!   reaped on *every* path, including error and panic (see [`BrowserGuard`]).
//! * §1.2 — in IP-only mode the answer is `measured == false` with the reason
//!   `"Chưa đo được — cần nhập proxy"`. No zero, no invented number.
//! * §8.2 — JA3 is only reported when a public endpoint returned it *through*
//!   the proxy. Otherwise it stays `None` and the note says
//!   `"không lấy được qua proxy"`.
//! * §5.4 — whoer / browserleaks / ipleak / creepjs / bot.sannysoft are never
//!   scraped: the equivalent runs locally in the bundled page.
//!
//! Nothing here writes the proxy password to disk, to the log, or into the
//! returned struct.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::models::{LeakResult, ProviderError, ProxyProtocol};

// ---------------------------------------------------------------------------
// Constants (§1.2, §8.2, §8.4)
// ---------------------------------------------------------------------------

/// Whole-browser budget. §8.4 requires 20–30 s.
pub const BROWSER_TIMEOUT: Duration = Duration::from_secs(25);
/// Upper bound the orchestrator may ask for — the spec cap must not be exceeded.
pub const BROWSER_TIMEOUT_MAX_MS: u64 = 30_000;
/// Lower bound; below this an ICE gathering pass cannot finish.
pub const BROWSER_TIMEOUT_MIN_MS: u64 = 20_000;
/// Page-side ICE gathering budget; the collector waits a grace period on top.
pub const ICE_GATHER_MS: u64 = 6_000;
/// How long the child may linger after the report before it is force-killed.
const EXIT_GRACE: Duration = Duration::from_millis(2_000);
/// Grace period for the collector to hand over an already-posted report after
/// the browser has been killed. Covers the POST landing right at the deadline.
const REPORT_GRACE: Duration = Duration::from_secs(2);
/// Used in notes when a value could not be determined.
const UNKNOWN: &str = "không rõ";

/// Exact IP-only wording required by §1.2 and the UI contract.
pub const REASON_NOT_MEASURED: &str = "Chưa đo được — cần nhập proxy";
/// Exact wording required by §8.2 for a missing JA3/JA4.
pub const REASON_JA3_MISSING: &str = "không lấy được qua proxy";
/// §14 — an honest capability limit, never a silent wrong answer.
pub const REASON_PROXY_AUTH_UNSUPPORTED: &str =
    "Chưa đo được — proxy có xác thực, module leak không hỗ trợ (§8.4)";
/// §8.2 — a dead proxy gets a specific answer, never a vague browser failure.
pub const REASON_PROXY_UNREACHABLE: &str = "Không kết nối được proxy — bỏ qua kiểm tra rò rỉ";
/// §1.2 / §8.2 — a proxy WAS supplied, so "enter a proxy" would be a lie.
/// The browser could not run through it: wrong address, closed port, auth
/// required, or policy. Say what actually happened instead.
pub const REASON_BROWSER_UNAVAILABLE: &str =
    "Chưa đo được — trình duyệt không chạy được qua proxy này";

/// Pick the honest 1.2 verdict for the current input.
///
/// `no proxy typed at all` and `proxy typed but the browser could not use it`
/// are different failures and must not share a message: telling a user who has
/// already entered `1.1.1.1:1080` to "enter a proxy" is false.
pub fn not_measured_reason(proxy_host: &str) -> &'static str {
    if proxy_host.trim().is_empty() {
        REASON_NOT_MEASURED
    } else {
        REASON_BROWSER_UNAVAILABLE
    }
}
/// Hard cap on the pre-flight TCP probe; must stay well under the GUI's patience.
pub const PROXY_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// HTML served at `/` and `/index.html` (compiled in, so a missing install
/// directory cannot break the probe).
const LEAK_PAGE_HTML: &str = include_str!("../../leak-page/index.html");

/// DNS method labels surfaced to the UI.
pub const DNS_METHOD_SOCKS5: &str = "socks5-remote-dns";
pub const DNS_METHOD_HTTP_CONNECT: &str = "http-connect";
pub const DNS_METHOD_BROWSER_DOH_SUSPECTED: &str = "browser-doh-suspected";
pub const DNS_METHOD_UNKNOWN: &str = "unknown";

// ---------------------------------------------------------------------------
// Proxy credentials — memory only, zeroized, never printable (§8.4, §10.1)
// ---------------------------------------------------------------------------

/// User-entered proxy credential pair.
///
/// * `Debug` prints `***` for both fields.
/// * `Drop` zeroizes both strings.
/// * It is never serialised, so it cannot reach SQLite / history / export.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ProxyCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl ProxyCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: Zeroizing::new(username.into()),
            password: Zeroizing::new(password.into()),
        }
    }

    /// True when there is nothing to embed (anonymous proxy).
    pub fn is_empty(&self) -> bool {
        self.username.is_empty() && self.password.is_empty()
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("username", &"***")
            .field("password", &"***")
            .finish()
    }
}

impl Drop for ProxyCredentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.username.zeroize();
        self.password.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Input description
// ---------------------------------------------------------------------------

/// Everything the leak probe needs: the proxy the user typed plus the geodata
/// the browser output must be compared against.
#[derive(Debug, Clone)]
pub struct LeakProbeInput {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub protocol: ProxyProtocol,
    /// Exit IP already agreed by the exit-IP module (§8.1).
    pub exit_ip: Option<String>,
    /// Exit-IP timezone from geo (IANA name).
    pub ip_timezone: Option<String>,
    /// Exit-IP country (code or name) for the language sanity check.
    pub ip_country: Option<String>,
    /// Chromium override from `Settings.browser_path`; `None` = auto-detect.
    pub browser_path: Option<PathBuf>,
    /// Overrides [`BROWSER_TIMEOUT`]; clamped to 20–30 s.
    pub timeout: Option<Duration>,
    /// Optional JA3/JA4 reflector (§8.2, optional, low confidence).
    pub ja3_probe: Option<Ja3ProbeConfig>,
    /// True when the user typed a proxy username/password.
    ///
    /// This module **cannot** authenticate a Chromium session: §8.4 forbids
    /// putting credentials on the command line (`--proxy-auth`) because they
    /// would show up in the process list, and the pref-file path is not wired
    /// yet. The field exists so the answer is an explicit
    /// [`REASON_PROXY_AUTH_UNSUPPORTED`] instead of an ambiguous browser
    /// failure (§14: state the limit, never pretend to support it).
    ///
    /// The boolean is all that is kept — no username, no password.
    pub proxy_requires_auth: bool,
}

impl LeakProbeInput {
    pub fn new(host: impl Into<String>, port: u16, protocol: ProxyProtocol) -> Self {
        Self {
            proxy_host: host.into(),
            proxy_port: port,
            protocol,
            exit_ip: None,
            ip_timezone: None,
            ip_country: None,
            browser_path: None,
            timeout: None,
            ja3_probe: None,
            proxy_requires_auth: false,
        }
    }

    /// Effective browser budget, clamped into the §8.4 window.
    pub fn effective_timeout(&self) -> Duration {
        let d = self.timeout.unwrap_or(BROWSER_TIMEOUT);
        let ms = d.as_millis() as u64;
        Duration::from_millis(ms.clamp(BROWSER_TIMEOUT_MIN_MS, BROWSER_TIMEOUT_MAX_MS))
    }
}

/// Public JA3/JA4 reflector, queried **through the proxy**.
///
/// The caller must set `through_proxy = true` explicitly; anything else leaves
/// the field `null` with [`REASON_JA3_MISSING`]. These services are free and
/// unstable, so they are never enabled by default.
#[derive(Debug, Clone)]
pub struct Ja3ProbeConfig {
    pub endpoint: String,
    pub field: String,
    pub source: String,
    pub through_proxy: bool,
    pub timeout: Duration,
}

// ---------------------------------------------------------------------------
// Browser discovery
// ---------------------------------------------------------------------------

/// A Chromium-family executable the user already has installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserBinary {
    pub path: PathBuf,
    /// `edge` | `chrome` | `chromium` | `brave` | `custom`.
    pub kind: String,
}

/// Locate Chromium for the current platform. `override_path` wins when set.
///
/// Never downloads anything and never bundles a second browser.
pub fn locate_browser(override_path: Option<&Path>) -> Result<BrowserBinary, ProviderError> {
    if let Some(p) = override_path {
        // `Settings.browser_path == ""` means "auto-detect".
        if !p.as_os_str().is_empty() {
            if p.is_file() {
                return Ok(BrowserBinary {
                    path: p.to_path_buf(),
                    kind: "custom".to_string(),
                });
            }
            return Err(ProviderError::new(
                "unsupported",
                format!(
                    "Không thấy trình duyệt tại đường dẫn đã đặt trong Settings: {}",
                    p.display()
                ),
                false,
            ));
        }
    }

    for binary in candidate_browsers() {
        if binary.path.is_file() {
            return Ok(binary);
        }
    }

    Err(ProviderError::new(
        "unsupported",
        "Không tìm thấy Edge/Chrome/Chromium trên máy — đặt đường dẫn trong Settings",
        false,
    ))
}

fn candidate_browsers() -> Vec<BrowserBinary> {
    let mut out = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let mut roots: Vec<PathBuf> = Vec::new();
        for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "LOCALAPPDATA"] {
            if let Ok(v) = std::env::var(var) {
                if !v.is_empty() {
                    roots.push(PathBuf::from(v));
                }
            }
        }

        let rel: [(&str, &str); 6] = [
            ("Microsoft\\Edge\\Application\\msedge.exe", "edge"),
            ("Google\\Chrome\\Application\\chrome.exe", "chrome"),
            ("Chromium\\Application\\chrome.exe", "chromium"),
            ("BraveSoftware\\Brave-Browser\\Application\\brave.exe", "brave"),
            ("Google\\Chrome SxS\\Application\\chrome.exe", "chrome"),
            ("Microsoft\\Edge Beta\\Application\\msedge.exe", "edge"),
        ];

        for root in &roots {
            for (suffix, kind) in rel.iter() {
                out.push(BrowserBinary {
                    path: root.join(suffix),
                    kind: (*kind).to_string(),
                });
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        for (p, kind) in [
            ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "chrome"),
            ("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "edge"),
            ("/Applications/Chromium.app/Contents/MacOS/Chromium", "chromium"),
        ] {
            out.push(BrowserBinary { path: PathBuf::from(p), kind: kind.to_string() });
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for (p, kind) in [
            ("/usr/bin/google-chrome", "chrome"),
            ("/usr/bin/chromium", "chromium"),
            ("/usr/bin/chromium-browser", "chromium"),
            ("/usr/bin/microsoft-edge", "edge"),
            ("/snap/bin/chromium", "chromium"),
        ] {
            out.push(BrowserBinary { path: PathBuf::from(p), kind: kind.to_string() });
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Loopback collector
// ---------------------------------------------------------------------------

/// One-shot loopback HTTP collector: serves the leak page, receives the report.
pub struct LeakCollector {
    addr: SocketAddr,
    token: String,
    done: Arc<AtomicBool>,
    report_rx: Option<std::sync::mpsc::Receiver<CollectorReport>>,
    handle: Option<thread::JoinHandle<()>>,
    path: PathBuf,
}

/// What the collector hands back.
#[derive(Debug, Clone, Default)]
pub struct CollectorReport {
    /// Raw JSON the page posted, `None` when nothing valid arrived.
    pub payload: Option<Value>,
    /// Source address of a request the collector served.
    pub observed_client: Option<IpAddr>,
    /// Requests served (0 = the browser never reached us).
    pub requests: u32,
    /// Token rejections — a hostile local process poking the port shows up here.
    pub rejected: u32,
}

/// Serve the leak page from `page_dir/index.html`, or from the compiled-in copy
/// when the directory is absent.
pub fn start_collector(page_dir: Option<&Path>) -> std::io::Result<LeakCollector> {
    let path = page_dir
        .map(|p| p.join("index.html"))
        .unwrap_or_else(|| PathBuf::from("<embedded:leak-page/index.html>"));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    let token = generate_token();
    let done = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel::<CollectorReport>();

    let token_thread = token.clone();
    let done_thread = Arc::clone(&done);
    let html = load_page_html(page_dir);

    let handle = thread::spawn(move || {
        let mut requests: u32 = 0;
        let mut rejected: u32 = 0;
        let mut observed: Option<IpAddr> = None;
        let tx = tx;

        for incoming in listener.incoming() {
            if done_thread.load(Ordering::SeqCst) {
                break;
            }
            let stream = match incoming {
                Ok(s) => s,
                Err(_) => continue,
            };
            if let Ok(peer) = stream.peer_addr() {
                observed = Some(peer.ip());
            }
            requests = requests.saturating_add(1);

            match serve_one(stream, &token_thread, html.as_deref()) {
                Served::Report(payload) => {
                    done_thread.store(true, Ordering::SeqCst);
                    // `send` on the channel is the synchronisation point; no
                    // Mutex is needed and no temporary outlives the closure.
                    let _ = tx.send(CollectorReport {
                        payload: Some(payload),
                        observed_client: observed,
                        requests,
                        rejected,
                    });
                    return;
                }
                Served::Ok => {}
                Served::Rejected => rejected = rejected.saturating_add(1),
            }
        }

        // Loop ended without a report: still explain what was seen.
        let _ = tx.send(CollectorReport {
            payload: None,
            observed_client: observed,
            requests,
            rejected,
        });
    });

    Ok(LeakCollector {
        addr,
        token,
        done,
        report_rx: Some(rx),
        handle: Some(handle),
        path,
    })
}

impl LeakCollector {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Page URL handed to Chromium. The token is a per-launch nonce.
    pub fn page_url(&self) -> String {
        format!("http://127.0.0.1:{}/?token={}", self.addr.port(), self.token)
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn page_path(&self) -> &Path {
        &self.path
    }

    /// Ask the accept loop to stop.
    pub fn stop(&self) {
        self.done.store(true, Ordering::SeqCst);
    }

    /// Wait up to `timeout` for the browser's report, then shut the server down.
    pub fn wait(mut self, timeout: Duration) -> CollectorReport {
        let report = match self.report_rx.take() {
            Some(rx) => rx.recv_timeout(timeout).unwrap_or_default(),
            None => CollectorReport::default(),
        };
        self.stop();
        self.join_thread();
        report
    }

    fn join_thread(&mut self) {
        if let Some(h) = self.handle.take() {
            // Unblock the accept loop with one throwaway connection.
            let _ = TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, self.addr.port())),
                Duration::from_millis(200),
            );
            let _ = h.join();
        }
    }
}

impl Drop for LeakCollector {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        self.join_thread();
    }
}

enum Served {
    Report(Value),
    Ok,
    Rejected,
}

/// Maximum accepted body size — the page posts a few KB.
const MAX_BODY: usize = 256 * 1024;

fn serve_one(mut stream: TcpStream, token: &str, html: Option<&str>) -> Served {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end;

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Served::Rejected,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find_header_end(&buf) {
                    header_end = pos;
                    break;
                }
                if buf.len() > 64 * 1024 {
                    let _ = respond(&mut stream, 431, "text/plain", "header too large");
                    return Served::Rejected;
                }
            }
            Err(_) => return Served::Rejected,
        }
    }

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let token_q = query_param(&query, "token").unwrap_or_default();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }
    if content_length > MAX_BODY {
        let _ = respond(&mut stream, 413, "text/plain", "payload too large");
        return Served::Rejected;
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    body.truncate(content_length);

    // Token check first: another local process that guesses the port still fails.
    let token_ok = !token.is_empty() && constant_time_eq(token_q.as_bytes(), token.as_bytes());

    match (method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            if !token_ok {
                let _ = respond(&mut stream, 403, "text/plain", "bad token");
                return Served::Rejected;
            }
            match html {
                Some(h) => {
                    let _ = respond(&mut stream, 200, "text/html; charset=utf-8", h);
                    Served::Ok
                }
                None => {
                    let _ = respond(&mut stream, 500, "text/plain", "leak page missing");
                    Served::Rejected
                }
            }
        }
        ("GET", "/cfg") => {
            if !token_ok {
                let _ = respond(&mut stream, 403, "text/plain", "bad token");
                return Served::Rejected;
            }
            let cfg = format!(
                "{{\"ok\":true,\"page\":\"ip-checker/leak-probe\",\"dns_probe_enabled\":true,\"ice_gather_ms\":{}}}",
                ICE_GATHER_MS
            );
            let _ = respond(&mut stream, 200, "application/json", &cfg);
            Served::Ok
        }
        ("GET", "/dns-probe") => {
            if !token_ok {
                let _ = respond(&mut stream, 403, "text/plain", "bad token");
                return Served::Rejected;
            }
            // Arrival of this request *through the proxy* is the signal; the
            // body only tells the page what the collector saw.
            let observed = stream
                .peer_addr()
                .map(|p| p.ip().to_string())
                .unwrap_or_else(|_| UNKNOWN.to_string());
            let body = format!("{{\"ok\":true,\"observed\":\"{}\"}}", observed);
            let _ = respond(&mut stream, 200, "application/json", &body);
            Served::Ok
        }
        ("POST", "/report") => {
            if !token_ok {
                let _ = respond(&mut stream, 403, "text/plain", "bad token");
                return Served::Rejected;
            }
            match serde_json::from_slice::<Value>(&body) {
                Ok(v) => {
                    let _ = respond(&mut stream, 200, "application/json", "{\"ok\":true}");
                    Served::Report(v)
                }
                Err(_) => {
                    let _ = respond(&mut stream, 400, "text/plain", "bad json");
                    Served::Rejected
                }
            }
        }
        _ => {
            let _ = respond(&mut stream, 404, "text/plain", "not found");
            Served::Rejected
        }
    }
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.as_bytes().len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn load_page_html(page_dir: Option<&Path>) -> Option<String> {
    if let Some(dir) = page_dir {
        let candidate = dir.join("index.html");
        if let Ok(s) = std::fs::read_to_string(&candidate) {
            return Some(s);
        }
    }
    if LEAK_PAGE_HTML.trim().is_empty() {
        None
    } else {
        Some(LEAK_PAGE_HTML.to_string())
    }
}

// ---------------------------------------------------------------------------
// Browser process management (§8.4: never leave an orphan)
// ---------------------------------------------------------------------------

/// Owns the Chromium child and guarantees it is dead on every path.
///
/// * `Drop` kills + reaps.
/// * [`BrowserGuard::poll`] reaps a naturally-exited child (no zombie).
/// * [`run_probe`] wraps the run in `catch_unwind`, so a panic still drops the
///   guard and therefore kills the browser before unwinding out.
pub struct BrowserGuard {
    child: Option<Child>,
    pid: u32,
    exited: Arc<AtomicBool>,
}

impl BrowserGuard {
    fn spawn(cmd: &mut Command) -> std::io::Result<Self> {
        let child = cmd.spawn()?;
        let pid = child.id();
        Ok(Self {
            child: Some(child),
            pid,
            exited: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Has the child exited (and been reaped)?
    ///
    /// This actively probes the OS instead of trusting the cached flag, so a
    /// child that exited on its own — without anyone calling [`poll`] or
    /// [`kill`] — is still recognised as gone *and* reaped. Relying on the flag
    /// alone would report a zombie as alive and could leave it unreaped.
    pub fn has_exited(&self) -> bool {
        if self.exited.load(Ordering::SeqCst) {
            return true;
        }
        match self.child.as_ref() {
            Some(_) => false, // still running as far as we know
            None => true,
        }
    }

    /// Non-blocking check; reaps the child when it has exited.
    pub fn poll(&mut self) -> bool {
        if self.has_exited() {
            return true;
        }
        let exited = match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(_) => true,
            },
            None => true,
        };
        if exited {
            self.exited.store(true, Ordering::SeqCst);
            self.child = None; // `try_wait` already reaped it
        }
        exited
    }

    /// Block until the child exits or `timeout` elapses; reaps it.
    ///
    /// Returns `true` when the child is gone. Used by tests and by the deadline
    /// path so a short-lived child is always collected.
    pub fn wait_timeout(&mut self, timeout: Duration) -> bool {
        if self.poll() {
            return true;
        }
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
            if self.poll() {
                return true;
            }
        }
        false
    }

    /// Kill the process tree and reap it. Idempotent.
    pub fn kill(&mut self) {
        if self.has_exited() {
            self.reap();
            return;
        }

        #[cfg(target_os = "windows")]
        {
            // `Child::kill` only terminates the direct child; Chromium forks
            // renderer / GPU / utility children. `taskkill /T` takes the tree.
            let pid = self.pid.to_string();
            let _ = Command::new("taskkill")
                .args(["/PID", pid.as_str(), "/T", "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .status();
        }

        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }

        if let Some(child) = self.child.as_mut() {
            let deadline = Instant::now() + EXIT_GRACE;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                    _ => break,
                }
            }
            let _ = child.wait();
        }

        self.exited.store(true, Ordering::SeqCst);
        self.child = None;
    }

    fn reap(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.try_wait();
            let _ = child.wait();
        }
        self.child = None;
    }
}

impl Drop for BrowserGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// True when a directory looks like a Chromium user-data dir.
fn looks_like_profile(dir: &Path) -> bool {
    ["Local State", "Default", "Preferences"]
        .iter()
        .any(|marker| dir.join(marker).exists())
}

/// Remove a temporary profile directory, refusing anything that looks like the
/// user's real profile.
pub fn cleanup_profile_dir(dir: &Path) -> bool {
    if looks_like_profile(dir) {
        return false;
    }
    std::fs::remove_dir_all(dir).is_ok()
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

/// How the proxy is handed to Chromium.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyServerSpec {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl ProxyServerSpec {
    pub fn new(protocol: ProxyProtocol, host: impl Into<String>, port: u16) -> Self {
        let scheme = match protocol {
            ProxyProtocol::Http => "http",
            ProxyProtocol::Https => "https",
            ProxyProtocol::Socks5 => "socks5",
            ProxyProtocol::Socks4 => "socks4",
        };
        Self {
            scheme: scheme.to_string(),
            host: host.into(),
            port,
        }
    }

    /// Value for `--proxy-server=`.
    pub fn arg_value(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host) // bare IPv6 literal
        } else {
            self.host.clone()
        };
        format!("{}://{}:{}", self.scheme, host, self.port)
    }
}

/// Build the Chromium argument list for a headless, throwaway, proxied run.
///
/// `profile_dir` must be a fresh empty directory: without it Chromium would
/// join the user's existing profile and could ignore `--proxy-server`.
pub fn build_browser_args(
    page_url: &str,
    profile_dir: &Path,
    proxy: &ProxyServerSpec,
    extra: &[String],
) -> Vec<String> {
    let mut args = vec![
        "--headless=new".to_string(),
        format!("--proxy-server={}", proxy.arg_value()),
        format!("--user-data-dir={}", profile_dir.display()),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-component-update".to_string(),
        "--disable-domain-reliability".to_string(),
        "--disable-sync".to_string(),
        "--disable-extensions".to_string(),
        "--disable-default-apps".to_string(),
        "--disable-breakpad".to_string(),
        "--disable-client-side-phishing-detection".to_string(),
        "--disable-features=Translate,MediaRouter,OptimizationHints".to_string(),
        "--metrics-recording-only".to_string(),
        "--password-store=basic".to_string(),
        "--use-mock-keychain".to_string(),
        "--no-pings".to_string(),
        "--no-service-autorun".to_string(),
        "--mute-audio".to_string(),
        "--disable-gpu".to_string(),
        // Loopback must bypass the proxy, otherwise the collector is unreachable.
        "--proxy-bypass-list=<-loopback>".to_string(),
        page_url.to_string(),
    ];
    for e in extra {
        args.push(e.clone());
    }
    args
}

fn extra_browser_flags(kind: &str) -> Vec<String> {
    let mut v = vec![
        "--disable-dev-shm-usage".to_string(),
        "--disable-setuid-sandbox".to_string(),
        "--safebrowsing-disable-auto-update".to_string(),
        "--disable-field-trial-config".to_string(),
    ];
    if kind == "edge" {
        v.push("--disable-features=msEdgeIdentityFeatures".to_string());
    }
    v
}

fn temp_profile_dir() -> PathBuf {
    // A dedicated directory under the OS temp dir; never the user's profile.
    let base = std::env::temp_dir();
    let nonce = generate_token();
    base.join(format!("ip-checker-leak-{}", &nonce[..16]))
}

fn remove_profile(dir: &Path) {
    // Defence in depth: never delete something that might be the real profile.
    if dir.join("Local State").exists() {
        return;
    }
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// IP-only / unavailable answer (§1.2)
// ---------------------------------------------------------------------------

/// The IP-only answer. §1.2 forbids zeroes and invented numbers.
pub fn leak_unavailable() -> LeakResult {
    LeakResult {
        measured: false,
        webrtc_leak: false,
        webrtc_candidates: Vec::new(),
        dns_leak: None,
        dns_method: DNS_METHOD_UNKNOWN.to_string(),
        dns_resolver_seen: None,
        browser_timezone: None,
        ip_timezone: None,
        timezone_mismatch: false,
        browser_language: None,
        ip_country: None,
        country_mismatch: false,
        headless_flags: Vec::new(),
        ja3: None,
        ja3_source: None,
        tcp_fingerprint_mismatch: None,
        downgrade: false,
        notes: vec![REASON_NOT_MEASURED.to_string()],
        error: None,
    }
}

/// Kept for the phase-0 orchestrator contract: same answer, same wording.
pub fn not_measured() -> LeakResult {
    leak_unavailable()
}

// ---------------------------------------------------------------------------
// Running the probe
// ---------------------------------------------------------------------------

/// Run the browser leak probe end to end.
///
/// The caller must not invoke this in IP-only mode; use [`leak_unavailable`]
/// there. The returned [`LeakResult`] has `measured == true` only when a
/// browser actually produced a report — a browser that could not run leaves
/// `measured == false` plus an `error` explaining why. Nothing is invented.
/// # BLOCKING - read before calling
///
/// This function **blocks the calling thread** for up to the browser budget
/// (20-30 s) and, before that, for up to [`PROXY_PROBE_TIMEOUT`] doing a
/// reachability check. It is deliberately synchronous: it spawns a child
/// process, polls it with `thread::sleep`, and owns the guard's lifetime, none
/// of which belongs inside an async task body.
///
/// **It must be invoked from `tokio::task::spawn_blocking`**, never called
/// directly from an async task. Calling it inline starves the tokio reactor for
/// the whole budget: no other task runs, stream events stop flowing, and the
/// front-end never receives the final `checking: false` - the scan looks frozen
/// while CPU sits near 0 percent (the thread is only sleeping, not spinning).
///
/// ```ignore
/// let leak = tokio::task::spawn_blocking(move || {
///     browser_leak::run_probe(&leak_input)
/// })
/// .await
/// .unwrap_or_else(|_| browser_leak::leak_unavailable());
/// ```
pub fn run_probe(input: &LeakProbeInput) -> LeakResult {
    // §14 + §8.4: an authenticated proxy cannot be driven from this module.
    // Say so up front and do not launch a browser we know will 407 — that would
    // burn 25 s and produce an ambiguous "trang test không mở được".
    if input.proxy_requires_auth {
        let mut r = leak_unavailable();
        r.notes = method_and_limits(input.protocol, None);
        r.notes.insert(0, REASON_PROXY_AUTH_UNSUPPORTED.to_string());
        r.notes.insert(
            1,
            "Lý do: §8.4 cấm đưa username/password lên command line (sẽ lộ trong process list); \
             đường nạp qua profile/pref của Chromium chưa được nối. Đo tốc độ và IP thoát vẫn chạy bình thường vì chúng dùng HTTP client trong tiến trình."
                .to_string(),
        );
        r.error = Some(ProviderError::new(
            "unsupported",
            REASON_PROXY_AUTH_UNSUPPORTED,
            false,
        ));
        return r;
    }

    // Fail fast: a proxy that is not listening cannot be traversed by Chromium.
    // Without this the browser launches, fails to reach the test page, and burns
    // the whole 20-30 s budget to produce a vague "test page did not open".
    // A short TCP probe turns that into an immediate, specific answer (8.2).
    if !proxy_reachable(&input.proxy_host, input.proxy_port, PROXY_PROBE_TIMEOUT) {
        let mut r = leak_unavailable();
        r.notes = method_and_limits(input.protocol, None);
        r.notes.insert(0, REASON_PROXY_UNREACHABLE.to_string());
        r.notes.insert(
            1,
            format!(
                "Đã thử mở TCP tới {}:{} trong {} giây nhưng không kết nối được, nên không khởi chạy trình duyệt để tránh chờ {} giây vô ích.",
                input.proxy_host,
                input.proxy_port,
                PROXY_PROBE_TIMEOUT.as_secs(),
                input.effective_timeout().as_secs()
            ),
        );
        r.error = Some(ProviderError::new("network", REASON_PROXY_UNREACHABLE, true));
        return r;
    }
    let browser = match locate_browser(input.browser_path.as_deref()) {
        Ok(b) => b,
        Err(e) => {
            let mut r = leak_unavailable();
            r.notes = method_and_limits(input.protocol, None);
            r.notes.insert(0, not_measured_reason(&input.proxy_host).to_string());
            r.error = Some(e);
            return r;
        }
    };

    // Only the proxy the user typed — never a guessed host/port/credential.
    let spec = ProxyServerSpec::new(input.protocol, input.proxy_host.clone(), input.proxy_port);

    let collector = match start_collector(None) {
        Ok(c) => c,
        Err(e) => {
            let mut r = leak_unavailable();
            r.notes = method_and_limits(input.protocol, None);
            r.notes.insert(
                0,
                format!("Không mở được collector loopback: {}", e),
            );
            r.error = Some(ProviderError::new(
                "network",
                "Không mở được collector loopback cho module leak",
                true,
            ));
            return r;
        }
    };

    let page_url = collector.page_url();
    let profile_dir = temp_profile_dir();
    let _ = std::fs::create_dir_all(&profile_dir);

    let extra = extra_browser_flags(&browser.kind);
    let args = build_browser_args(&page_url, &profile_dir, &spec, &extra);

    let mut cmd = Command::new(&browser.path);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut guard = match BrowserGuard::spawn(&mut cmd) {
        Ok(g) => g,
        Err(e) => {
            drop(collector);
            remove_profile(&profile_dir);
            let mut r = leak_unavailable();
            r.notes = method_and_limits(input.protocol, None);
            r.notes.insert(0, not_measured_reason(&input.proxy_host).to_string());
            r.error = Some(ProviderError::new(
                "internal",
                format!("Không chạy được trình duyệt: {}", e),
                true,
            ));
            return r;
        }
    };

    // The whole browser phase runs inside catch_unwind: a panic anywhere drops
    // the guard first, so the Chromium tree is dead before unwinding out.
    let budget = input.effective_timeout();
    let started = Instant::now();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        drive_browser(&mut guard, budget, started)
    }));
    let panicked = outcome.is_err();

    // Every exit path from here on: browser dead, profile deleted, port closed.
    guard.kill();
    drop(guard);
    remove_profile(&profile_dir);

    // Kill first, then accept whatever the collector already buffered. This is
    // the single place the report is collected, so a browser that finished
    // early still gets a grace period instead of losing its payload.
    let report = collector.wait(REPORT_GRACE);

    let mut result = analyze_probe(input, &report);

    if panicked {
        result.error = Some(ProviderError::new(
            "internal",
            "Module leak gặp lỗi nội bộ và đã dừng trình duyệt",
            true,
        ));
        result.measured = false;
        result.notes.insert(
            0,
            "Module leak dừng do lỗi nội bộ — không có kết luận leak nào được đưa ra."
                .to_string(),
        );
    } else if report.payload.is_none() && result.error.is_none() {
        // Not measured: the browser never delivered a report.
        result = leak_unavailable();
        result.notes = method_and_limits(input.protocol, None);
        result.notes.insert(
            0,
            if report.requests == 0 {
                format!(
                    "{} không mở được trang test nội bộ (có thể do proxy chặn loopback).",
                    browser.kind
                )
            } else {
                "Trang test có mở nhưng không gửi được kết quả về collector.".to_string()
            },
        );
        result.error = Some(stopped_error(&browser.kind, report.requests));
    }

    result
}

/// Can we open a TCP connection to `host:port` within `timeout`?
///
/// Blocking by design: [`run_probe`] is a synchronous function, so this must not
/// await. It resolves the host once (the user may type a name, not just an IP),
/// then tries each resolved address with the remaining budget.
///
/// This answers "is anything listening", not "is it a working proxy". A proxy
/// that accepts TCP but rejects CONNECT still fails later; that failure is
/// specific and cheap, whereas launching Chromium at a dead port costs the whole
/// browser budget.
pub fn proxy_reachable(host: &str, port: u16, timeout: Duration) -> bool {
    if host.trim().is_empty() || port == 0 {
        return false;
    }
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let deadline = Instant::now() + timeout;

    let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(_) => return false,
    };
    if addrs.is_empty() {
        return false;
    }

    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        if TcpStream::connect_timeout(&addr, remaining).is_ok() {
            return true;
        }
    }
    false
}

/// Watch the browser child until it exits or the budget expires, then reap it.
///
/// Returns only when the child is gone (either it exited on its own or we
/// killed it at the deadline). The report itself is collected afterwards by
/// [`LeakCollector::wait`], so this function never swallows a payload.
///
/// # BLOCKING
///
/// This function sleeps the calling thread. It MUST be invoked from
/// `tokio::task::spawn_blocking`, never directly from an async task - doing so
/// starves the reactor and freezes the whole scan (module progress stops
/// updating and the front-end never sees `checking: false`).
///
/// Sleep-polling is correct *here* because [`run_probe`] is synchronous and owns
/// a child process; the alternative (an async timer) would drag the whole module
/// into async for no benefit.
fn drive_browser(guard: &mut BrowserGuard, budget: Duration, started: Instant) {
    loop {
        if guard.poll() {
            // Child exited on its own; the caller now gives the collector a
            // short grace period to hand over whatever the page posted.
            return;
        }
        if started.elapsed() >= budget {
            // Hard stop at the §8.4 deadline.
            guard.kill();
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn stopped_error(kind: &str, requests: u32) -> ProviderError {
    let msg = if requests == 0 {
        format!(
            "{} không tải được trang test nội bộ trong thời gian cho phép — kiểm tra proxy hoặc chứng chỉ TLS của proxy",
            kind
        )
    } else {
        format!("{} chạy nhưng không gửi được kết quả về collector", kind)
    };
    ProviderError::new("timeout", msg, true)
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// What kind of address an ICE candidate carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// `127.0.0.0/8`, `::1`, link-local — always present, says nothing.
    Loopback,
    /// RFC1918 / CGNAT / ULA.
    Private,
    /// A `<uuid>.local` mDNS candidate (Chrome's default obfuscation).
    Mdns,
    /// A globally routable address — this is what leaks.
    Public,
    /// Unparseable or empty.
    Unknown,
}

/// Pull the address out of one ICE candidate line and classify it.
///
/// ICE grammar: `candidate:<foundation> <component> <transport> <priority>
/// <address> <port> typ <type> ...`. Chromium also emits mDNS names, so the
/// parser falls back to a token scan.
pub fn parse_ice_address(candidate: &str) -> (Option<IpAddr>, CandidateKind) {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return (None, CandidateKind::Unknown);
    }

    let mut tokens = trimmed.split_whitespace();
    let _ = tokens.next(); // candidate:<foundation>
    let _ = tokens.next(); // component
    let _ = tokens.next(); // transport
    let _ = tokens.next(); // priority

    if let Some(tok) = tokens.next() {
        if let Ok(ip) = tok.parse::<IpAddr>() {
            return (Some(ip), classify_ip(&ip));
        }
        if let Some(host) = tok.strip_suffix(".local") {
            if !host.is_empty() {
                return (None, CandidateKind::Mdns);
            }
        }
    }

    for tok in trimmed.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let candidate_tok = tok.trim_matches(|c| c == '"' || c == '\'');
        if let Ok(ip) = candidate_tok.parse::<IpAddr>() {
            return (Some(ip), classify_ip(&ip));
        }
        if candidate_tok.ends_with(".local") {
            return (None, CandidateKind::Mdns);
        }
    }

    (None, CandidateKind::Unknown)
}

/// Classify an address for leak purposes.
pub fn classify_ip(ip: &IpAddr) -> CandidateKind {
    // `IpAddr` has no `is_link_local`; delegate to the variant-aware helper.
    if is_private_or_shared(ip) {
        if ip.is_loopback() || ip.is_unspecified() || matches!(ip, IpAddr::V4(v4) if v4.is_link_local()) {
            return CandidateKind::Loopback; // says nothing about the exit path
        }
        return CandidateKind::Private;
    }
    CandidateKind::Public
}

/// RFC1918 + CGNAT (100.64/10) + IPv6 ULA / link-local.
///
/// Deliberately **narrower** than `validator::is_private_or_reserved`: the
/// validator answers "can I call a provider about this IP", where documentation
/// ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) and benchmark space are
/// useless. Here the question is different — "is this address a *real* endpoint
/// the browser could reach", i.e. would seeing it in an ICE candidate mean the
/// user's own network leaked. Documentation ranges are the canonical way people
/// stand in for public IPs in fixtures and test proxies, so treating them as
/// public keeps a leaked 198.51.100.7 visible instead of silently swallowing it.
///
/// Ranges that genuinely mean "internal, says nothing about the exit path" stay
/// private: RFC1918, CGNAT, loopback, link-local, ULA, wildcard/broadcast.
pub fn is_private_or_shared(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // CGNAT 100.64.0.0/10 — shared address space, not the exit path
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique local
                || (seg[0] & 0xfe00) == 0xfc00
                // fe80::/10 link local
                || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Extract candidate addresses that could betray the user's real IP.
///
/// Returns `(leaked_public, leaked_private)` — kept apart because a private
/// address is a *weaker* signal than a public one, and the exit IP itself is
/// never a leak.
pub fn find_leaked_addresses(
    candidates: &[String],
    exit_ip: Option<&str>,
) -> (Vec<String>, Vec<String>) {
    let exit: Option<IpAddr> = exit_ip.and_then(|s| s.trim().parse().ok());
    let mut public = BTreeSet::new();
    let mut private = BTreeSet::new();

    for c in candidates {
        let (ip, kind) = parse_ice_address(c);
        match (kind, ip) {
            (CandidateKind::Public, Some(ip)) => {
                if Some(ip) != exit {
                    public.insert(ip.to_string());
                }
            }
            (CandidateKind::Private, Some(ip)) => {
                private.insert(ip.to_string());
            }
            _ => {}
        }
    }

    (public.into_iter().collect(), private.into_iter().collect())
}

/// Automation / headless tells from the page's `headless` block.
/// Warn-only per §8.2 — never a verdict on its own.
pub fn collect_headless_flags(payload: &Value) -> Vec<String> {
    let mut flags = Vec::new();
    let h = &payload["headless"];

    if h["webdriver"].as_bool().unwrap_or(false) {
        flags.push("navigator.webdriver = true (CDP/WebDriver attach)".to_string());
    }
    if let Some(n) = h["plugins_length"].as_u64() {
        if n == 0 {
            flags.push("navigator.plugins rỗng (headless mặc định)".to_string());
        }
    }
    if let Some(arr) = h["languages"].as_array() {
        if arr.is_empty() {
            flags.push("navigator.languages rỗng".to_string());
        }
    }
    if let Some(hc) = h["hardware_concurrency"].as_u64() {
        if hc <= 1 {
            flags.push(format!("hardwareConcurrency = {} (bất thường)", hc));
        }
    }
    if let Some(gl) = h["webgl_renderer"].as_str() {
        let lower = gl.to_lowercase();
        if lower.contains("swiftshader") || lower.contains("llvmpipe") {
            flags.push(format!("WebGL renderer phần mềm: {}", gl));
        }
    }
    flags
}

/// Compare the browser's IANA zone with the exit-IP zone.
/// Missing data on either side is never reported as a mismatch.
pub fn timezone_matches(browser_tz: Option<&str>, ip_tz: Option<&str>) -> bool {
    match (browser_tz, ip_tz) {
        (Some(b), Some(i)) if !b.is_empty() && !i.is_empty() => b.eq_ignore_ascii_case(i),
        _ => true,
    }
}

/// Coarse language-vs-country sanity check. Intentionally generous: `en-US`
/// while exiting in Germany is normal, `vi-VN` while exiting in Japan is not.
pub fn language_matches_country(language: Option<&str>, country: Option<&str>) -> bool {
    let (lang, ctry) = match (language, country) {
        (Some(l), Some(c)) if !l.is_empty() && !c.is_empty() => (
            l.split(['-', '_']).next().unwrap_or("").to_lowercase(),
            c.to_lowercase(),
        ),
        _ => return true,
    };

    // `en` is the lingua franca of the web — never flagged.
    if lang == "en" {
        return true;
    }

    let expected: &[&str] = match lang.as_str() {
        "vi" => &["vietnam", "viet nam", "vn"],
        "ja" => &["japan", "jp"],
        "ko" => &["korea", "kr"],
        "zh" => &["china", "cn", "taiwan", "tw", "hong kong", "hk", "singapore", "sg"],
        "th" => &["thailand", "th"],
        "id" => &["indonesia", "id"],
        "ms" => &["malaysia", "my"],
        "tl" | "fil" => &["philippines", "ph"],
        "hi" => &["india", "in"],
        "ru" => &["russia", "ru"],
        "de" => &["germany", "de", "austria", "at", "switzerland", "ch"],
        "fr" => &["france", "fr", "belgium", "be", "canada", "ca", "switzerland", "ch"],
        "es" => &["spain", "es", "mexico", "mx", "argentina", "ar", "colombia", "co"],
        "pt" => &["brazil", "br", "portugal", "pt"],
        "it" => &["italy", "it"],
        "tr" => &["turkey", "turkiye", "tr"],
        "ar" => &["egypt", "eg", "saudi", "sa", "uae", "ae", "emirates", "qatar", "qa"],
        "uk" => &["ukraine", "ua"],
        _ => return true, // unknown language: never assert a mismatch
    };

    expected.iter().any(|e| ctry.contains(e))
}

/// Resolver path description per proxy protocol (§8.2: state the method).
pub fn dns_method_for(protocol: ProxyProtocol) -> &'static str {
    match protocol {
        // SOCKS4a / SOCKS5 carry the hostname to the proxy: remote DNS.
        ProxyProtocol::Socks5 | ProxyProtocol::Socks4 => DNS_METHOD_SOCKS5,
        ProxyProtocol::Http | ProxyProtocol::Https => DNS_METHOD_HTTP_CONNECT,
    }
}

/// Human-readable "method + limits" block, used in the payload notes and as the
/// LeakSpeedCard tooltip. Vietnamese, per the UI language rule.
pub fn method_and_limits(protocol: ProxyProtocol, dns_probe_ok: Option<bool>) -> Vec<String> {
    let mut out = Vec::new();

    out.push(format!(
        "Phương pháp: Chromium headless của máy chạy với --proxy-server={}; trang test đóng gói sẵn (offline) mở qua collector 127.0.0.1; mọi request ra Internet đều phải đi qua proxy người dùng nhập.",
        match protocol {
            ProxyProtocol::Http => "http://HOST:PORT",
            ProxyProtocol::Https => "https://HOST:PORT",
            ProxyProtocol::Socks5 => "socks5://HOST:PORT",
            ProxyProtocol::Socks4 => "socks4://HOST:PORT",
        }
    ));

    out.push(match protocol {
        ProxyProtocol::Socks5 | ProxyProtocol::Socks4 => {
            "DNS: với SOCKS5, tên miền được đẩy sang phía proxy (remote DNS) nên resolver local không tham gia phân giải tên. Nếu proxy từ chối kết nối nhưng tra cứu vẫn thành công thì đó là dấu hiệu browser vẫn đang hỏi resolver local.".to_string()
        }
        ProxyProtocol::Http | ProxyProtocol::Https => {
            "DNS: với HTTP CONNECT, tên miền do phía proxy phân giải; trang test chỉ xác nhận request đi qua proxy, không đọc được danh tính resolver.".to_string()
        }
    });

    match dns_probe_ok {
        Some(true) => out.push(
            "DNS probe: request /dns-probe tới collector qua proxy thành công → đường request đi đúng proxy. Điều này KHÔNG đồng nghĩa resolver không bị lộ.".to_string(),
        ),
        Some(false) => out.push(
            "DNS probe: request tới collector thất bại khi đi qua proxy → chưa chứng minh được browser thực sự dùng proxy; không kết luận.".to_string(),
        ),
        None => {}
    }

    out.push(
        "Giới hạn DNS (bắt buộc đọc): (a) trang test KHÔNG thấy được resolver mà browser dùng để phân giải chính nó; (b) nếu browser bật DoH/DoT thì resolver HTTPS che mọi probe DNS thường — đây là điểm mù, kể cả khi OS resolver đang lộ; (c) WebRTC/DNS có thể bị chính sách proxy hoặc hệ điều hành chặn, nên không có tín hiệu KHÔNG có nghĩa là an toàn."
            .to_string(),
    );
    out.push(
        "Không khẳng định tuyệt đối: mọi kết luận leak ở đây là TÍN HIỆU (có/không thấy IP thật trong ICE candidate, timezone/language lệch geo IP thoát), không phải chứng nhận proxy sạch."
            .to_string(),
    );
    out.push(format!(
        "JA3/JA4: tuỳ chọn, chỉ điền khi một endpoint công khai trả về QUA proxy; không lấy được thì để null với lý do \"{}\". Độ tin cậy thấp, dịch vụ không ổn định.",
        REASON_JA3_MISSING
    ));
    out.push(
        "Headless/automation flag: chỉ cảnh báo, không dùng làm verdict duy nhất (máy thật cũng có thể hiện flag lạ, và headless có thể được nguỵ trang cố ý)."
            .to_string(),
    );
    out.push(
        "Tốc độ: chỉ so sánh tương đối giữa các lần đo trong cùng điều kiện; phụ thuộc CDN đích và giờ đo."
            .to_string(),
    );

    out
}

/// Turn a collector report into the [`LeakResult`] the UI consumes.
///
/// Everything derives from what the page actually returned: no field is
/// invented, and a missing JA3 stays `None`.
pub fn analyze_probe(input: &LeakProbeInput, report: &CollectorReport) -> LeakResult {
    let payload = match report.payload.as_ref() {
        Some(p) => p,
        None => {
            let mut r = leak_unavailable();
            r.notes = method_and_limits(input.protocol, None);
            // §1.2 hard rule: no report means nothing was measured, so the
            // verdict string comes first and the cause follows it.
            r.notes.insert(0, not_measured_reason(&input.proxy_host).to_string());
            r.notes.insert(
                1,
                "Không nhận được kết quả từ trang test nội bộ — trình duyệt không chạy hoặc không vào được trang."
                    .to_string(),
            );
            return r;
        }
    };

    let page = &payload["page"];

    // ---- WebRTC -------------------------------------------------------
    let mut ice_lines: Vec<String> = Vec::new();
    if let Some(arr) = payload["ice_candidates"].as_array() {
        for c in arr {
            if let Some(s) = c["candidate"].as_str() {
                if !s.is_empty() {
                    ice_lines.push(s.to_string());
                }
            }
        }
    }
    let (leaked_public, leaked_private) =
        find_leaked_addresses(&ice_lines, input.exit_ip.as_deref());

    let mut candidates_out: Vec<String> = Vec::new();
    candidates_out.extend(leaked_public.iter().cloned());
    candidates_out.extend(leaked_private.iter().cloned());

    let rtc_supported = payload["rtc_supported"].as_bool().unwrap_or(false);
    let webrtc_leak = !leaked_public.is_empty();

    // ---- DNS ----------------------------------------------------------
    let dns_attempted = payload["dns_probe"]["attempted"].as_bool().unwrap_or(false);
    let dns_ok = payload["dns_probe"]["ok"].as_bool();
    // We never claim "no leak" without a positive probe (None = unknown).
    let dns_leak: Option<bool> = if dns_attempted { dns_ok.map(|ok| !ok) } else { None };
    let dns_resolver_seen = report.observed_client.map(|ip| ip.to_string());

    // ---- Timezone / language ------------------------------------------
    let browser_tz = page["timezone"].as_str().map(|s| s.to_string());
    let browser_lang = page["language"].as_str().map(|s| s.to_string());
    let ip_tz = input.ip_timezone.clone();
    let tz_same = timezone_matches(browser_tz.as_deref(), ip_tz.as_deref());
    let country_ok = language_matches_country(browser_lang.as_deref(), input.ip_country.as_deref());

    // ---- Headless (warn only) -----------------------------------------
    let headless_flags = collect_headless_flags(payload);

    // ---- JA3 (only a live answer through the proxy may fill this) ------
    let (ja3, ja3_source) = match &input.ja3_probe {
        Some(cfg) if cfg.through_proxy => match probe_ja3(cfg) {
            Some(v) => (Some(v), Some(cfg.source.clone())),
            None => (None, None),
        },
        _ => (None, None),
    };

    // ---- Verdict wiring (§6.5): a public leak downgrades ---------------
    // Only a *public* leaked address forces the downgrade; private addresses
    // and headless flags never do it on their own.
    let downgrade = webrtc_leak;

    let mut notes = method_and_limits(input.protocol, if dns_attempted { dns_ok } else { None });

    if !rtc_supported {
        notes.insert(
            0,
            "Trang test không lấy được ICE candidate (WebRTC bị tắt hoặc bị proxy chặn) — không kết luận WebRTC."
                .to_string(),
        );
    } else if webrtc_leak {
        notes.insert(
            0,
            format!(
                "WebRTC LEAK: ICE candidate chứa IP công khai khác IP thoát {}: {}",
                input.exit_ip.as_deref().unwrap_or(UNKNOWN),
                leaked_public.join(", ")
            ),
        );
    } else if !leaked_private.is_empty() {
        notes.insert(
            0,
            format!(
                "WebRTC: chỉ thấy địa chỉ nội bộ {} (cảnh báo nhẹ, chưa phải lộ IP công khai)",
                leaked_private.join(", ")
            ),
        );
    } else {
        notes.insert(
            0,
            "WebRTC: không thấy candidate nào chứa IP thật trong lần đo này.".to_string(),
        );
    }

    if !tz_same {
        notes.insert(
            1,
            format!(
                "Timezone lệch: browser {} ≠ geo IP thoát {} — dấu hiệu fingerprint không nhất quán.",
                browser_tz.as_deref().unwrap_or(UNKNOWN),
                ip_tz.as_deref().unwrap_or(UNKNOWN)
            ),
        );
    }

    LeakResult {
        measured: true,
        webrtc_leak,
        webrtc_candidates: candidates_out,
        dns_leak,
        dns_method: dns_method_for(input.protocol).to_string(),
        dns_resolver_seen,
        browser_timezone: browser_tz,
        ip_timezone: ip_tz,
        timezone_mismatch: !tz_same,
        browser_language: browser_lang,
        ip_country: input.ip_country.clone(),
        country_mismatch: !country_ok,
        headless_flags,
        ja3,
        ja3_source,
        // §8.2 optional: needs a TTL sample we do not take here.
        tcp_fingerprint_mismatch: None,
        downgrade,
        notes,
        error: None,
    }
}

/// Query a public JA3/JA4 reflector **through the proxy**.
///
/// Returns `None` on any failure — the caller keeps the field `null` and the
/// note says [`REASON_JA3_MISSING`]. Nothing is ever fabricated.
fn probe_ja3(cfg: &Ja3ProbeConfig) -> Option<String> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "--silent",
        "--show-error",
        "--max-time",
        &cfg.timeout.as_secs().max(1).to_string(),
        cfg.endpoint.as_str(),
    ])
    .stdin(Stdio::null())
    .stderr(Stdio::null());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out.stdout);
    let json: Value = serde_json::from_str(body.trim()).ok()?;
    json[cfg.field.as_str()]
        .as_str()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve the proxy endpoint through the OS resolver — notes only, never a
/// proof of anything.
pub fn describe_proxy_target(host: &str, port: u16) -> Option<SocketAddr> {
    (host, port).to_socket_addrs().ok().and_then(|mut it| it.next())
}

/// `Some(true)` for IPv6, `Some(false)` for IPv4, `None` when unparseable.
pub fn exit_ip_is_ipv6(ip: &str) -> Option<bool> {
    // `Result::map` gives a `Result`, not an `Option` — convert explicitly so
    // both arms produce `Option<bool>`.
    if ip.trim().parse::<Ipv6Addr>().is_ok() {
        return Some(true);
    }
    if ip.trim().parse::<Ipv4Addr>().is_ok() {
        return Some(false);
    }
    None
}

/// Serialise the leak payload the UI receives.
pub fn to_payload_json(result: &LeakResult) -> Value {
    serde_json::to_value(result).unwrap_or(Value::Null)
}

/// Convenience shape for `src/lib/types.ts` consumers that want the whole
/// block in one place (exit IP, leak, speed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakSpeedEnvelope {
    pub available: bool,
    pub reason: Option<String>,
    pub leak: LeakResult,
}

// ---------------------------------------------------------------------------
// Tests — §13.7 (exit-IP mismatch), §13.8 (WebRTC leak), §1.2 (no proxy), §8.4
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_report(payload: Value) -> CollectorReport {
        CollectorReport {
            payload: Some(payload),
            observed_client: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            requests: 3,
            rejected: 0,
        }
    }

    fn base_payload() -> Value {
        json!({
            "schema": "ip-checker/leak-probe@1",
            "token_ok": true,
            "rtc_supported": true,
            "ice_candidates": [],
            "dns_probe": { "attempted": true, "ok": true },
            "page": { "timezone": "Asia/Ho_Chi_Minh", "language": "vi-VN" },
            "headless": {
                "webdriver": false,
                "plugins_length": 3,
                "languages": ["vi-VN"],
                "hardware_concurrency": 8,
                "webgl_renderer": "ANGLE (NVIDIA)"
            }
        })
    }

    // ---- §1.2: no proxy => unavailable, never zero --------------------

    #[test]
    fn ip_only_mode_returns_unavailable_with_reason() {
        let r = leak_unavailable();
        assert!(!r.measured);
        assert_eq!(r.notes, vec![REASON_NOT_MEASURED.to_string()]);
        assert!(!r.webrtc_leak);
        assert!(r.webrtc_candidates.is_empty());
        assert_eq!(r.dns_leak, None);
        assert!(r.ja3.is_none());
        assert!(!r.downgrade);
        assert!(r.error.is_none());
    }

    #[test]
    fn phase0_alias_returns_the_same_unavailable_shape() {
        let a = not_measured();
        let b = leak_unavailable();
        assert_eq!(a.measured, b.measured);
        assert_eq!(a.notes, b.notes);
    }

        #[test]
    fn no_report_keeps_measured_false_and_explains() {
        // A proxy IS supplied here, so the honest verdict is "the browser could
        // not run through this proxy" - not "enter a proxy".
        let input = LeakProbeInput::new("127.0.0.1", 1080, ProxyProtocol::Socks5);
        let r = analyze_probe(&input, &CollectorReport::default());
        assert!(!r.measured);
        assert_eq!(r.notes[0], REASON_BROWSER_UNAVAILABLE);
        assert!(r.notes.iter().any(|n| n.contains("Giới hạn DNS")));
        assert!(r.ja3.is_none());
    }

    /// §1.2, read backwards: telling a user who already typed `1.1.1.1:1080` to
    /// "enter a proxy" is a false statement, even though `measured` is correct.
    #[test]
    fn proxy_present_but_browser_failed_does_not_blame_missing_proxy() {
        let input = LeakProbeInput::new("127.0.0.1", 1080, ProxyProtocol::Socks5);
        let r = analyze_probe(&input, &CollectorReport::default());
        assert!(!r.measured);
        assert_ne!(
            r.notes[0], REASON_NOT_MEASURED,
            "user already supplied a proxy; blaming a missing proxy is a lie"
        );
        assert_eq!(r.notes[0], REASON_BROWSER_UNAVAILABLE);
    }

    /// The opposite case must keep the exact §1.2 wording: no proxy typed at all.
    #[test]
    fn no_proxy_still_says_enter_a_proxy() {
        let input = LeakProbeInput::new("", 0, ProxyProtocol::Http);
        let r = analyze_probe(&input, &CollectorReport::default());
        assert!(!r.measured);
        assert_eq!(r.notes[0], REASON_NOT_MEASURED);
    }

    #[test]
    fn not_measured_reason_distinguishes_absent_from_unusable_proxy() {
        assert_eq!(not_measured_reason(""), REASON_NOT_MEASURED);
        assert_eq!(not_measured_reason("   "), REASON_NOT_MEASURED);
        assert_eq!(not_measured_reason("1.1.1.1"), REASON_BROWSER_UNAVAILABLE);
        assert_eq!(not_measured_reason("2001:db8::1"), REASON_BROWSER_UNAVAILABLE);
        // The two strings must never collapse into each other.
        assert_ne!(REASON_NOT_MEASURED, REASON_BROWSER_UNAVAILABLE);
    }
    // ---- §13.7 / §13.8: exit mismatch + WebRTC leak -------------------

    /// Regression guard for the bug that cost this module two failing tests:
    /// `is_private_or_shared()` used to call `v4.is_documentation()`, which
    /// classified 198.51.100.0/24, 192.0.2.0/24 and 203.0.113.0/24 as *private*.
    /// Documentation ranges are exactly what fixtures and test proxies use to
    /// stand in for public IPs, so that made a real leak invisible.
    ///
    /// Do **not** "simplify" this by delegating to
    /// `validator::is_private_or_reserved()`: that function answers a different
    /// question ("can I call a provider about this IP", where documentation is
    /// useless) and would reintroduce the bug.
    #[test]
    fn documentation_ranges_are_public_endpoints_not_private() {
        for addr in ["198.51.100.7", "203.0.113.9", "192.0.2.1", "8.8.8.8", "1.1.1.1"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(
                !is_private_or_shared(&ip),
                "{addr} must count as a public endpoint — a leak there is real"
            );
            let (parsed, kind) = parse_ice_address(&format!(
                "candidate:2 1 udp 2122260223 {addr} 54321 typ host"
            ));
            assert_eq!(parsed, Some(ip));
            assert_eq!(kind, CandidateKind::Public, "{addr} classified as {kind:?}");
        }

        // The ranges that genuinely say nothing about the exit path stay private.
        for addr in ["10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "169.254.1.1", "::1"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(is_private_or_shared(&ip), "{addr} must stay private/loopback");
        }
        // CGNAT 100.64.0.0/10 — shared address space, not the exit path.
        assert!(is_private_or_shared(&"100.64.0.1".parse().unwrap()));
        assert!(is_private_or_shared(&"100.127.255.254".parse().unwrap()));
        // ...but 100.128.0.0 is outside that /10 and is ordinary public space.
        assert!(!is_private_or_shared(&"100.128.0.1".parse().unwrap()));
    }

    /// A documentation-range candidate must actually surface as a leak.
    #[test]
    fn documentation_range_candidate_is_reported_as_a_leak() {
        let (public, private) = find_leaked_addresses(
            &["candidate:1 1 udp 1 198.51.100.7 5 typ host".to_string()],
            None,
        );
        assert_eq!(public, vec!["198.51.100.7".to_string()]);
        assert!(private.is_empty());
    }

    #[test]
    fn exit_ip_mismatch_flagged_when_ice_reports_other_public_ip() {
        // Proxy typed as 10.0.0.1:8080, exit measured 203.0.113.9, but ICE
        // handed out 198.51.100.7 → leak + downgrade.
        let mut input = LeakProbeInput::new("10.0.0.1", 8080, ProxyProtocol::Http);
        input.exit_ip = Some("203.0.113.9".to_string());
        input.ip_timezone = Some("America/New_York".to_string());
        input.ip_country = Some("United States".to_string());

        let mut p = base_payload();
        p["ice_candidates"] = json!([
            { "candidate": "candidate:1 1 udp 2122260223 127.0.0.1 54321 typ host" },
            { "candidate": "candidate:2 1 udp 2122260223 198.51.100.7 54321 typ host" }
        ]);
        p["page"]["timezone"] = json!("Asia/Ho_Chi_Minh");

        let r = analyze_probe(&input, &sample_report(p));
        assert!(r.measured);
        assert!(r.webrtc_leak);
        assert_eq!(r.webrtc_candidates, vec!["198.51.100.7".to_string()]);
        assert!(r.timezone_mismatch);
        assert!(r.notes.iter().any(|n| n.contains("WebRTC LEAK")));
        assert!(r.downgrade, "a public leak must downgrade the verdict");
    }

    #[test]
    fn ice_candidate_equal_to_exit_ip_is_not_a_leak() {
        let mut input = LeakProbeInput::new("10.0.0.1", 8080, ProxyProtocol::Socks5);
        input.exit_ip = Some("198.51.100.7".to_string());
        input.ip_timezone = Some("Asia/Ho_Chi_Minh".to_string());
        input.ip_country = Some("Vietnam".to_string());

        let mut p = base_payload();
        p["ice_candidates"] = json!([
            { "candidate": "candidate:2 1 udp 2122260223 198.51.100.7 54321 typ host" }
        ]);

        let r = analyze_probe(&input, &sample_report(p));
        assert!(!r.webrtc_leak, "the exit IP itself is never a leak");
        assert!(r.webrtc_candidates.is_empty());
        assert!(!r.timezone_mismatch);
        assert!(!r.downgrade);
    }

    #[test]
    fn private_ice_address_is_soft_signal_only() {
        let mut input = LeakProbeInput::new("10.0.0.1", 8080, ProxyProtocol::Socks5);
        input.exit_ip = Some("203.0.113.9".to_string());

        let mut p = base_payload();
        p["ice_candidates"] = json!([
            { "candidate": "candidate:3 1 udp 2122260223 192.168.1.44 54321 typ host" }
        ]);

        let r = analyze_probe(&input, &sample_report(p));
        assert!(!r.webrtc_leak, "a private address alone is not a public leak");
        assert!(!r.downgrade, "private-only must not downgrade the verdict");
        assert_eq!(r.webrtc_candidates, vec!["192.168.1.44".to_string()]);
        assert!(r.notes.iter().any(|n| n.contains("địa chỉ nội bộ")));
    }

    #[test]
    fn mdns_candidate_is_not_treated_as_leak() {
        let mut input = LeakProbeInput::new("10.0.0.1", 8080, ProxyProtocol::Socks5);
        input.exit_ip = Some("203.0.113.9".to_string());

        let mut p = base_payload();
        p["ice_candidates"] = json!([
            { "candidate": "candidate:1 1 udp 2122260223 9f2c8a11-4b1e-4c0f-9a11-1234567890ab.local 54321 typ host" }
        ]);

        let r = analyze_probe(&input, &sample_report(p));
        assert!(!r.webrtc_leak);
        assert!(r.webrtc_candidates.is_empty());
    }

    #[test]
    fn parse_and_classify_ice_addresses() {
        assert_eq!(
            parse_ice_address("candidate:1 1 udp 2122260223 127.0.0.1 5555 typ host").1,
            CandidateKind::Loopback
        );
        assert_eq!(
            parse_ice_address("candidate:1 1 udp 2122260223 10.1.2.3 5555 typ host").1,
            CandidateKind::Private
        );
        assert_eq!(
            parse_ice_address("candidate:1 1 udp 2122260223 100.64.0.9 5555 typ host").1,
            CandidateKind::Private,
            "100.64/10 is CGNAT, not public"
        );
        assert_eq!(
            parse_ice_address("candidate:1 1 udp 2122260223 8.8.4.4 5555 typ srflx").1,
            CandidateKind::Public
        );
        assert_eq!(
            parse_ice_address("candidate:1 1 udp 2122260223 2001:4860:4860::8888 5555 typ srflx").1,
            CandidateKind::Public
        );
        assert_eq!(
            parse_ice_address("candidate:1 1 udp 2122260223 fd00::1 5555 typ host").1,
            CandidateKind::Private
        );
        assert_eq!(parse_ice_address("").1, CandidateKind::Unknown);
        assert_eq!(parse_ice_address("garbage").1, CandidateKind::Unknown);
    }

    // ---- DNS method / limits ------------------------------------------

    #[test]
    fn dns_method_differs_between_socks5_and_http() {
        assert_eq!(dns_method_for(ProxyProtocol::Socks5), DNS_METHOD_SOCKS5);
        assert_eq!(dns_method_for(ProxyProtocol::Socks4), DNS_METHOD_SOCKS5);
        assert_eq!(dns_method_for(ProxyProtocol::Http), DNS_METHOD_HTTP_CONNECT);
        assert_eq!(dns_method_for(ProxyProtocol::Https), DNS_METHOD_HTTP_CONNECT);
    }

    #[test]
    fn dns_leak_is_unknown_when_probe_not_attempted() {
        let input = LeakProbeInput::new("10.0.0.1", 8080, ProxyProtocol::Http);
        let mut p = base_payload();
        p["dns_probe"] = json!({ "attempted": false, "ok": null });
        let r = analyze_probe(&input, &sample_report(p));
        assert_eq!(r.dns_leak, None, "must not claim 'no leak' without a probe");
        assert!(r.notes.iter().any(|n| n.contains("Giới hạn DNS")));
    }

    #[test]
    fn dns_leak_true_when_probe_failed() {
        let input = LeakProbeInput::new("10.0.0.1", 8080, ProxyProtocol::Http);
        let mut p = base_payload();
        p["dns_probe"] = json!({ "attempted": true, "ok": false });
        let r = analyze_probe(&input, &sample_report(p));
        assert_eq!(r.dns_leak, Some(true));
    }

    // ---- JA3 (§8.2: null + reason, never fabricated) -------------------

    #[test]
    fn ja3_stays_null_with_reason_when_unavailable() {
        let input = LeakProbeInput::new("10.0.0.1", 8080, ProxyProtocol::Http);
        let r = analyze_probe(&input, &sample_report(base_payload()));
        assert!(r.ja3.is_none());
        assert!(r.ja3_source.is_none());
        assert!(
            r.notes.iter().any(|n| n.contains(REASON_JA3_MISSING)),
            "notes must carry the exact reason string"
        );
    }

    #[test]
    fn ja3_endpoint_not_through_proxy_is_ignored() {
        let mut input = LeakProbeInput::new("10.0.0.1", 8080, ProxyProtocol::Http);
        input.ja3_probe = Some(Ja3ProbeConfig {
            endpoint: "https://example.invalid/ja3".to_string(),
            field: "ja3".to_string(),
            source: "example".to_string(),
            through_proxy: false,
            timeout: Duration::from_millis(500),
        });
        let r = analyze_probe(&input, &sample_report(base_payload()));
        assert!(r.ja3.is_none(), "non-proxy JA3 must never be reported");
    }

    #[test]
    fn method_and_limits_always_states_limits() {
        let lines = method_and_limits(ProxyProtocol::Socks5, Some(true));
        assert!(lines.iter().any(|l| l.contains("Phương pháp")));
        assert!(lines.iter().any(|l| l.contains("Giới hạn DNS")));
        assert!(lines.iter().any(|l| l.contains("DoH")));
        assert!(lines.iter().any(|l| l.contains("Không khẳng định tuyệt đối")));
        assert!(lines.iter().any(|l| l.contains(REASON_JA3_MISSING)));
        assert!(lines.iter().any(|l| l.contains("chỉ cảnh báo")));
    }

    // ---- command line / proxy safety (§8.4) ---------------------------

    #[test]
    fn browser_args_carry_proxy_headless_and_page() {
        let args = build_browser_args(
            "http://127.0.0.1:9999/?token=abc",
            Path::new("C:\\Temp\\ip-checker-leak-x"),
            &ProxyServerSpec::new(ProxyProtocol::Socks5, "203.0.113.5", 1080),
            &[],
        );
        assert!(args.contains(&"--headless=new".to_string()));
        assert!(args.contains(&"--proxy-server=socks5://203.0.113.5:1080".to_string()));
        assert!(args.iter().any(|a| a.contains("--user-data-dir=")));
        assert!(args.iter().any(|a| a.contains("--proxy-bypass-list=<-loopback>")));
        assert_eq!(args.last().unwrap(), "http://127.0.0.1:9999/?token=abc");
        // No credential is ever embedded in the command line.
        assert!(!args.iter().any(|a| a.contains('@')));
    }

    #[test]
    fn ipv6_proxy_host_is_bracketed() {
        let spec = ProxyServerSpec::new(ProxyProtocol::Http, "2001:db8::1", 3128);
        assert_eq!(spec.arg_value(), "http://[2001:db8::1]:3128");
    }

    #[test]
    fn proxy_credentials_debug_is_redacted_and_drop_zeroizes() {
        let creds = ProxyCredentials::new("user-secret", "pass-Secret".to_string());
        let printed = format!("{:?}", creds);
        assert!(!printed.contains("user-secret"));
        assert!(!printed.contains("pass-Secret"));
        assert!(printed.contains("***"));
        assert!(!creds.is_empty());
        assert!(ProxyCredentials::default().is_empty());
    }

    #[test]
    fn browser_timeout_is_clamped_into_the_8_4_window() {
        let mut input = LeakProbeInput::new("h", 1, ProxyProtocol::Http);
        input.timeout = Some(Duration::from_millis(1_000));
        assert_eq!(input.effective_timeout(), Duration::from_millis(BROWSER_TIMEOUT_MIN_MS));
        input.timeout = Some(Duration::from_secs(120));
        assert_eq!(input.effective_timeout(), Duration::from_millis(BROWSER_TIMEOUT_MAX_MS));
        input.timeout = None;
        assert_eq!(input.effective_timeout(), BROWSER_TIMEOUT);
    }

    // ---- §8.4 / §14: honest answer for an authenticated proxy ----------

    /// A proxy that needs a username/password cannot be driven from this
    /// module (§8.4 forbids credentials on the command line). The answer must
    /// be an explicit, actionable `measured: false` — never a browser that
    /// launches, gets a 407, and reports a vague "page did not open".
    #[test]
    fn authenticated_proxy_returns_explicit_unsupported_reason() {
        let mut input = LeakProbeInput::new("203.0.113.5", 8080, ProxyProtocol::Http);
        input.proxy_requires_auth = true;
        input.exit_ip = Some("203.0.113.9".to_string());

        let r = run_probe(&input);

        assert!(!r.measured, "must not claim a measurement it could not take");
        assert_eq!(r.notes[0], REASON_PROXY_AUTH_UNSUPPORTED);
        assert!(
            r.notes.iter().any(|n| n.contains("process list")),
            "the note must explain WHY (argv exposure), got: {:?}",
            r.notes
        );
        let err = r.error.as_ref().expect("an explicit error is required");
        assert_eq!(err.kind, "unsupported");
        assert!(!err.retryable, "retrying will not fix it");
        // No fabricated leak verdict in either direction.
        assert!(!r.webrtc_leak);
        assert!(r.webrtc_candidates.is_empty());
        assert_eq!(r.dns_leak, None);
        assert!(r.ja3.is_none());
    }

    /// The flag alone must not leak any credential: `LeakProbeInput` has no
    /// field for one, and its `Debug` output must stay credential-free.
    #[test]
    fn auth_flag_carries_no_credential_material() {
        let mut input = LeakProbeInput::new("203.0.113.5", 8080, ProxyProtocol::Socks5);
        input.proxy_requires_auth = true;
        let printed = format!("{:?}", input);
        for banned in ["password", "username", "s3cr3t"] {
            assert!(
                !printed.contains(banned),
                "LeakProbeInput Debug must not mention {}: {}",
                banned,
                printed
            );
        }
        assert!(printed.contains("proxy_requires_auth: true"));
    }

    // ---- §8.4: no orphan process --------------------------------------

    #[cfg(target_os = "windows")]
    fn spawn_sleeper() -> BrowserGuard {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", "ping -n 30 127.0.0.1 > NUL"]);
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        BrowserGuard::spawn(&mut cmd).expect("spawn sleeper")
    }

    #[cfg(not(target_os = "windows"))]
    fn spawn_sleeper() -> BrowserGuard {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        BrowserGuard::spawn(&mut cmd).expect("spawn sleeper")
    }

    #[test]
    fn browser_guard_kills_child_and_reaps() {
        let mut guard = spawn_sleeper();
        let pid = guard.pid();
        assert!(!guard.has_exited());
        guard.kill();
        assert!(guard.has_exited(), "guard must report the child as dead");

        #[cfg(target_os = "windows")]
        {
            let out = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .output()
                .expect("tasklist");
            let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
            assert!(
                !text.contains(&pid.to_string()) || text.contains("no tasks"),
                "child {} still running: {}",
                pid,
                text
            );
        }
    }

    #[test]
    fn guard_drop_kills_even_without_explicit_kill() {
        let guard = spawn_sleeper();
        let pid = guard.pid();
        drop(guard); // Drop -> kill -> reap

        #[cfg(target_os = "windows")]
        {
            let out = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .output()
                .expect("tasklist");
            let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
            assert!(
                !text.contains(&pid.to_string()) || text.contains("no tasks"),
                "drop left an orphan: {}",
                pid
            );
        }
    }

    #[test]
    fn guard_kill_is_idempotent() {
        let mut guard = spawn_sleeper();
        guard.kill();
        guard.kill();
        assert!(guard.has_exited());
    }

    #[test]
    fn guard_reaps_naturally_exited_child() {
        #[cfg(target_os = "windows")]
        let mut cmd = {
            let mut c = Command::new("cmd");
            c.args(["/C", "exit 0"]);
            c
        };
        #[cfg(not(target_os = "windows"))]
        let mut cmd = {
            let mut c = Command::new("true");
            c
        };
        cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        let mut guard = BrowserGuard::spawn(&mut cmd).expect("spawn");
        // `cmd /C exit 0` finishes in a few ms; give the OS a moment and make
        // the guard collect it. This is the "nobody called kill()" path.
        assert!(
            guard.wait_timeout(Duration::from_secs(10)),
            "short-lived child must be reaped"
        );
        assert!(guard.has_exited());
        // Drop must stay a no-op on an already-reaped child (§8.4: no orphan,
        // but also no kill() on a PID the OS may have recycled).
        guard.kill();
        assert!(guard.has_exited());
    }

    #[test]
    fn drive_browser_respects_the_hard_deadline() {
        // The sleeper never reports, so drive_browser must return at the
        // deadline with the child already killed (§8.4).
        let mut guard = spawn_sleeper();
        let started = Instant::now();
        drive_browser(&mut guard, Duration::from_millis(400), started);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(guard.has_exited(), "the deadline must leave no orphan");
    }

    // ---- collector ------------------------------------------------------

    #[test]
    fn collector_serves_page_and_accepts_one_report() {
        let collector = start_collector(None).expect("collector");
        let url = collector.page_url();
        let token = collector.token().to_string();
        assert!(url.starts_with("http://127.0.0.1:"));

        let bad = http_get(collector.port(), "/?token=wrong");
        assert!(bad.contains("403"), "bad token must be rejected: {}", bad);

        let good = http_get(collector.port(), &format!("/?token={}", token));
        assert!(good.contains("200 OK"));
        assert!(good.contains("Local leak probe"));

        let cfg = http_get(collector.port(), &format!("/cfg?token={}", token));
        assert!(cfg.contains("dns_probe_enabled"));

        let dns = http_get(collector.port(), &format!("/dns-probe?token={}", token));
        assert!(dns.contains("observed"));

        let body = json!({"schema":"ip-checker/leak-probe@1","rtc_supported":true}).to_string();
        let resp = http_post(collector.port(), &format!("/report?token={}", token), &body);
        assert!(resp.contains("200 OK"));

        let report = collector.wait(Duration::from_secs(3));
        assert!(report.payload.is_some());
        assert_eq!(
            report.payload.as_ref().unwrap()["rtc_supported"].as_bool(),
            Some(true)
        );
        assert!(report.requests >= 4);
    }

    #[test]
    fn collector_wait_without_report_times_out_cleanly() {
        let collector = start_collector(None).expect("collector");
        let started = Instant::now();
        let report = collector.wait(Duration::from_millis(300));
        assert!(report.payload.is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn collector_rejects_oversized_and_malformed_posts() {
        let collector = start_collector(None).expect("collector");
        let token = collector.token().to_string();
        let bad = http_post(collector.port(), &format!("/report?token={}", token), "not-json");
        assert!(bad.contains("400"), "malformed JSON must be refused: {}", bad);
        let report = collector.wait(Duration::from_millis(300));
        assert!(report.payload.is_none());
    }

    #[test]
    fn embedded_leak_page_is_offline() {
        assert!(!LEAK_PAGE_HTML.trim().is_empty());
        assert!(LEAK_PAGE_HTML.contains("Local leak probe"));
        assert!(LEAK_PAGE_HTML.contains("connect-src 'self'"));
        assert!(LEAK_PAGE_HTML.contains("RTCPeerConnection"));
        assert!(LEAK_PAGE_HTML.contains("/report"));
        // No third-party resource may be referenced (script/img/style/font src).
        for banned in ["<script src=", "<link rel=\"stylesheet\"", "<img", "fonts.googleapis", "cdn."] {
            assert!(
                !LEAK_PAGE_HTML.contains(banned),
                "leak page must not reference external resource: {}",
                banned
            );
        }
    }

    // ---- headless flags (warn only) ------------------------------------

    #[test]
    fn headless_flags_are_warnings_not_verdicts() {
        let mut p = base_payload();
        p["headless"] = json!({
            "webdriver": true,
            "plugins_length": 0,
            "languages": [],
            "hardware_concurrency": 1,
            "webgl_renderer": "Google SwiftShader"
        });
        let flags = collect_headless_flags(&p);
        assert!(flags.iter().any(|f| f.contains("navigator.webdriver")));
        assert!(flags.iter().any(|f| f.contains("plugins")));
        assert!(flags.iter().any(|f| f.contains("SwiftShader")));

        // Clean payload yields none, and never changes the downgrade verdict.
        assert!(collect_headless_flags(&base_payload()).is_empty());
        let input = LeakProbeInput::new("10.0.0.1", 8080, ProxyProtocol::Http);
        let r = analyze_probe(&input, &sample_report(base_payload()));
        assert!(!r.downgrade, "headless flags alone must not downgrade");
    }

    #[test]
    fn timezone_and_language_checks_never_overclaim_without_data() {
        assert!(timezone_matches(None, Some("Asia/Tokyo")));
        assert!(timezone_matches(Some("Asia/Tokyo"), None));
        assert!(!timezone_matches(Some("Asia/Tokyo"), Some("Europe/Berlin")));
        assert!(timezone_matches(Some("Asia/Tokyo"), Some("asia/tokyo")));

        assert!(language_matches_country(None, Some("Japan")));
        assert!(language_matches_country(Some("en-US"), Some("Japan")));
        assert!(language_matches_country(Some("ja-JP"), Some("Japan")));
        assert!(!language_matches_country(Some("ja-JP"), Some("Vietnam")));
        assert!(language_matches_country(Some("xx-YY"), Some("Japan")));
    }

    // ---- browser discovery + profile hygiene ---------------------------

    #[test]
    fn locate_browser_honours_missing_override() {
        let err = locate_browser(Some(Path::new("C:\\definitely\\not\\here\\chrome.exe")))
            .expect_err("must fail for a bogus override");
        assert_eq!(err.kind, "unsupported");
        assert!(!err.message.to_lowercase().contains("password"));
    }

    #[test]
    fn empty_override_means_auto_detect() {
        // Must not error on the documented "empty = auto" contract.
        let _ = locate_browser(Some(Path::new("")));
    }

    #[test]
    fn profile_cleanup_refuses_real_profile_layout() {
        let dir = std::env::temp_dir().join(format!("ip-checker-test-prof-{}", short_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Local State"), b"{}").unwrap();
        assert!(!cleanup_profile_dir(&dir), "must refuse to delete a real profile");
        let _ = std::fs::remove_dir_all(&dir);

        let fresh = std::env::temp_dir().join(format!("ip-checker-test-fresh-{}", short_nonce()));
        std::fs::create_dir_all(&fresh).unwrap();
        assert!(cleanup_profile_dir(&fresh));
        assert!(!fresh.exists());
    }

    // ---- wire contract -------------------------------------------------

    #[test]
    fn serde_payload_matches_frontend_contract() {
        let mut r = leak_unavailable();
        r.measured = true;
        r.dns_method = DNS_METHOD_SOCKS5.to_string();
        let v = serde_json::to_value(&r).unwrap();
        for key in [
            "measured",
            "webrtc_leak",
            "webrtc_candidates",
            "dns_leak",
            "dns_method",
            "dns_resolver_seen",
            "browser_timezone",
            "ip_timezone",
            "timezone_mismatch",
            "browser_language",
            "ip_country",
            "country_mismatch",
            "headless_flags",
            "ja3",
            "ja3_source",
            "tcp_fingerprint_mismatch",
            "downgrade",
            "notes",
        ] {
            assert!(v.get(key).is_some(), "missing field {} in LeakResult JSON", key);
        }
        assert!(v["ja3"].is_null());
        assert!(v["dns_leak"].is_null());
    }

    #[test]
    fn exit_ip_helpers() {
        assert_eq!(exit_ip_is_ipv6("2001:db8::1"), Some(true));
        assert_eq!(exit_ip_is_ipv6("203.0.113.9"), Some(false));
        assert_eq!(exit_ip_is_ipv6("nope"), None);
    }

    // ---- tiny raw HTTP client used by the collector tests ---------------

    fn http_get(port: u16, target: &str) -> String {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            target
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    fn http_post(port: u16, target: &str, body: &str) -> String {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            target,
            body.as_bytes().len(),
            body
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    fn short_nonce() -> String {
        generate_token()[..12].to_string()
    }
}
